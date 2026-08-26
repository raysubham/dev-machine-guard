package secureuserfile

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

const (
	MaxBytes        = 1 << 20
	FileMode        = os.FileMode(0o600)
	ParentMode      = os.FileMode(0o700)
	maxSymlinkDepth = 8
	maxBackups      = 3
)

var (
	ErrTargetUnusable  = errors.New("secure user file: target unusable")
	ErrNoTargetUser    = errors.New("secure user file: no enforceable target user")
	ErrAbsoluteSymlink = fmt.Errorf("secure user file: absolute symlink: %w", ErrTargetUnusable)
	ErrSymlinkLoop     = fmt.Errorf("secure user file: symlink chain too deep: %w", ErrTargetUnusable)
	ErrDanglingSymlink = fmt.Errorf("secure user file: symlink target does not exist: %w", ErrTargetUnusable)
	ErrWriteUnverified = errors.New("secure user file: write could not be verified or rolled back")
)

// Home pins all managed file operations beneath one resolved user's home.
type Home struct {
	targetUser *user.User
	home       string
	uid, gid   int
	root       *os.Root
	owners     ownerReader
	metadata   metadataReader

	randomSuffix      func() (string, error)
	afterParentCreate func(relativePath string)
	applyMetadata     func(*Home, *os.File, os.FileMode, bool) error
	getenv            func(string) string
	logf              func(format string, args ...any)
}

// File owns safe byte and metadata operations for one relative path.
type File struct {
	home         *Home
	relativePath string
	backupPrefix string
	maxBytes     int64
	pending      *secureFileSnapshot
}

type secureFileSnapshot struct {
	data      []byte
	existed   bool
	mode      os.FileMode
	leaf      string
	committed os.FileInfo
	removed   bool
}

type ownerReader interface {
	ownerUIDGID(f *os.File) (uid, gid uint32, enforced bool, err error)
}

type metadataReader interface {
	secure(f *os.File, home *Home, want os.FileMode) (bool, error)
}

func OpenUserHome(exec executor.Executor) (*Home, error) {
	if exec.IsRoot() && !interactiveSessionOK() {
		return nil, ErrNoTargetUser
	}
	u, err := exec.LoggedInUser()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoTargetUser, err)
	}
	home, err := openHome(u)
	if err == nil {
		home.getenv = executor.NewUserAwareExecutor(exec, u.Username).Getenv
	}
	return home, err
}

func openHome(u *user.User) (*Home, error) {
	if u == nil || u.HomeDir == "" {
		return nil, errors.New("secure user file: resolved user has no home directory")
	}
	uid, gid, err := secureUserIDs(u)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(u.HomeDir)
	if err != nil {
		return nil, fmt.Errorf("secure user file: open home root %q: %w", u.HomeDir, err)
	}
	owners := newOwnerReader()
	metadata, ok := owners.(metadataReader)
	if !ok {
		_ = root.Close()
		return nil, errors.New("secure user file: platform metadata reader unavailable")
	}
	return &Home{
		targetUser:    u,
		home:          u.HomeDir,
		uid:           uid,
		gid:           gid,
		root:          root,
		owners:        owners,
		metadata:      metadata,
		randomSuffix:  randomSuffix,
		applyMetadata: applySecureMetadata,
		getenv:        os.Getenv,
	}, nil
}

func (h *Home) Username() string {
	if h == nil || h.targetUser == nil {
		return ""
	}
	return h.targetUser.Username
}

func (h *Home) Close() error {
	if h == nil || h.root == nil {
		return nil
	}
	err := h.root.Close()
	h.root = nil
	return err
}

// Open pins one home-relative file and applies strict platform metadata.
func (h *Home) Open(relativePath, backupPrefix string, maxBytes int64) (*File, error) {
	clean, err := cleanSecureRelativePath(relativePath)
	if err != nil {
		return nil, err
	}
	if backupPrefix == "" || strings.ContainsAny(backupPrefix, `/\\`) {
		return nil, fmt.Errorf("secure user file: invalid backup prefix: %w", ErrTargetUnusable)
	}
	if maxBytes <= 0 || maxBytes > MaxBytes {
		return nil, fmt.Errorf("secure user file: invalid read limit: %w", ErrTargetUnusable)
	}
	return &File{home: h, relativePath: clean, backupPrefix: backupPrefix, maxBytes: maxBytes}, nil
}

func cleanSecureRelativePath(path string) (string, error) {
	if path == "" || filepath.IsAbs(path) {
		return "", fmt.Errorf("secure user file: path must be relative: %w", ErrTargetUnusable)
	}
	clean := filepath.Clean(path)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("secure user file: path escapes home: %w", ErrTargetUnusable)
	}
	return clean, nil
}

func removeCreatedParent(parent *os.Root, component string, created os.FileInfo) error {
	info, err := parent.Lstat(component)
	if err != nil {
		return fmt.Errorf("secure user file: inspect failed parent cleanup %q: %w", component, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() || !os.SameFile(info, created) {
		return fmt.Errorf("secure user file: created parent %q changed before cleanup: %w", component, ErrTargetUnusable)
	}
	if err := parent.Remove(component); err != nil {
		return fmt.Errorf("secure user file: remove failed parent %q: %w", component, err)
	}
	return nil
}

// EnsureParent creates missing parent components without traversing symlinks.
func (h *Home) EnsureParent(relativePath string) error {
	clean, err := cleanSecureRelativePath(relativePath)
	if err != nil {
		return err
	}
	mode := ParentMode
	parent := filepath.Dir(clean)
	if parent == "." {
		return nil
	}

	current, err := h.root.OpenRoot(".")
	if err != nil {
		return fmt.Errorf("secure user file: pin home: %w", err)
	}
	defer func() { _ = current.Close() }()
	currentRel := ""
	for _, component := range strings.Split(parent, string(filepath.Separator)) {
		created := false
		var createdInfo os.FileInfo
		info, lerr := current.Lstat(component)
		if errors.Is(lerr, os.ErrNotExist) {
			if err := current.Mkdir(component, mode); err != nil {
				return fmt.Errorf("secure user file: create parent %q: %w", component, err)
			}
			created = true
			createdInfo, lerr = current.Lstat(component)
			if lerr != nil {
				return fmt.Errorf("secure user file: inspect created parent %q: %w", component, lerr)
			}
			createdRel := filepath.Join(currentRel, component)
			if h.afterParentCreate != nil {
				h.afterParentCreate(createdRel)
			}
			info, lerr = current.Lstat(component)
		}
		if lerr != nil {
			return fmt.Errorf("secure user file: inspect parent %q: %w", component, lerr)
		}
		if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("secure user file: parent %q is not a real directory: %w", component, ErrTargetUnusable)
		}
		if created && !os.SameFile(createdInfo, info) {
			return fmt.Errorf("secure user file: parent %q changed after creation: %w", component, ErrTargetUnusable)
		}

		next, handle, err := h.pinDirectory(current, component)
		if err != nil {
			if created {
				return errors.Join(err, removeCreatedParent(current, component, createdInfo))
			}
			return err
		}
		if created {
			if err := h.applyMetadata(h, handle, mode, true); err != nil {
				_ = handle.Close()
				_ = next.Close()
				return errors.Join(err, removeCreatedParent(current, component, createdInfo))
			}
		}
		if err := h.VerifyOwner(handle, component); err != nil {
			_ = handle.Close()
			_ = next.Close()
			if created {
				return errors.Join(err, removeCreatedParent(current, component, createdInfo))
			}
			return err
		}
		_ = handle.Close()
		_ = current.Close()
		current = next
		currentRel = filepath.Join(currentRel, component)
	}
	return nil
}

func (h *Home) pinDirectory(parent *os.Root, component string) (*os.Root, *os.File, error) {
	child, err := parent.OpenRoot(component)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, nil, fmt.Errorf("secure user file: pin parent %q: %w", component, err)
		}
		return nil, nil, fmt.Errorf("secure user file: pin parent %q: %w", component, ErrTargetUnusable)
	}
	handle, err := child.Open(".")
	if err != nil {
		_ = child.Close()
		return nil, nil, fmt.Errorf("secure user file: open pinned parent %q: %w", component, err)
	}
	hi, err := handle.Stat()
	if err != nil {
		_ = handle.Close()
		_ = child.Close()
		return nil, nil, fmt.Errorf("secure user file: stat pinned parent %q: %w", component, err)
	}
	li, err := parent.Lstat(component)
	if err != nil || li.Mode()&fs.ModeSymlink != 0 || !li.IsDir() || !os.SameFile(li, hi) {
		_ = handle.Close()
		_ = child.Close()
		return nil, nil, fmt.Errorf("secure user file: parent %q changed while pinning: %w", component, ErrTargetUnusable)
	}
	return child, handle, nil
}

// VerifyOwner checks that an opened target belongs to the resolved user.
func (h *Home) VerifyOwner(f *os.File, name string) error {
	uid, _, enforced, err := h.owners.ownerUIDGID(f)
	if err != nil {
		return fmt.Errorf("secure user file: read owner: %w", err)
	}
	if enforced && uid != uint32(h.uid) { // #nosec G115 -- uid is parsed from os/user on POSIX
		return fmt.Errorf("secure user file: %q owned by uid %d, not target user: %w", name, uid, ErrTargetUnusable)
	}
	return checkSecurePlatformOwner(h, f)
}

func (f *File) applyMetadata(file *os.File, mode os.FileMode, directory bool) error {
	return f.home.applyMetadata(f.home, file, mode, directory)
}

// Path returns the pinned user's home directory.
func (h *Home) Path() string {
	if h == nil {
		return ""
	}
	return h.home
}

// Getenv reads an environment variable in the resolved user's context.
func (h *Home) Getenv(name string) string {
	if h == nil || h.getenv == nil {
		return ""
	}
	return h.getenv(name)
}

func (f *File) Location() string {
	if f == nil || f.home == nil {
		return ""
	}
	return filepath.Join(f.home.home, f.relativePath)
}

// RelativePath returns the cleaned path beneath the pinned home.
func (f *File) RelativePath() string {
	if f == nil {
		return ""
	}
	return f.relativePath
}

// ParentPresent reports whether every parent is an existing real directory.
func (f *File) ParentPresent() (bool, error) {
	parent := filepath.Dir(f.relativePath)
	if parent == "." {
		return true, nil
	}
	current := ""
	for _, component := range strings.Split(parent, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := f.home.root.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("secure user file: inspect parent: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return false, fmt.Errorf("secure user file: parent is not a real directory: %w", ErrTargetUnusable)
		}
	}
	return true, nil
}

func (f *File) log(format string, args ...any) {
	if f.home.logf != nil {
		f.home.logf(format, args...)
	}
}

type secureResolvedTarget struct {
	child *os.Root
	base  string
	rel   string
}

func (rt *secureResolvedTarget) close() {
	if rt != nil && rt.child != nil {
		_ = rt.child.Close()
	}
}

func (f *File) resolveLeaf() (*secureResolvedTarget, error) {
	rel, err := f.resolveLeafPath(false)
	if err != nil {
		return nil, err
	}
	return f.pin(rel)
}

func (f *File) resolveLeafPath(allowMissingSymlinkTarget bool) (string, error) {
	cur := f.relativePath
	viaSymlink := false
	for depth := 0; ; depth++ {
		if depth > maxSymlinkDepth {
			return "", ErrSymlinkLoop
		}
		info, err := f.home.root.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) {
			if viaSymlink && !allowMissingSymlinkTarget {
				return "", ErrDanglingSymlink
			}
			return cur, nil
		}
		if err != nil {
			return "", fmt.Errorf("secure user file: lstat %q: %w", cur, err)
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			return cur, nil
		}
		target, err := f.home.root.Readlink(cur)
		if err != nil {
			return "", fmt.Errorf("secure user file: readlink %q: %w", cur, err)
		}
		if isAbsSymlinkTarget(target) {
			return "", ErrAbsoluteSymlink
		}
		if endsInSeparatorOrDot(target) {
			return "", fmt.Errorf("secure user file: directory-shaped symlink: %w", ErrTargetUnusable)
		}
		next := filepath.Clean(filepath.Join(filepath.Dir(cur), target))
		if next == ".." || strings.HasPrefix(next, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("secure user file: symlink escapes home: %w", ErrTargetUnusable)
		}
		cur = next
		viaSymlink = true
	}
}

func (f *File) pin(rel string) (*secureResolvedTarget, error) {
	parent := filepath.Dir(rel)
	base := filepath.Base(rel)
	if base == "." || base == ".." || strings.ContainsRune(base, filepath.Separator) {
		return nil, fmt.Errorf("secure user file: invalid leaf %q: %w", rel, ErrTargetUnusable)
	}
	child, err := f.pinParent(parent)
	if err != nil {
		return nil, err
	}
	return &secureResolvedTarget{child: child, base: base, rel: rel}, nil
}

func (f *File) pinParent(parent string) (*os.Root, error) {
	current, err := f.home.root.OpenRoot(".")
	if err != nil {
		return nil, fmt.Errorf("secure user file: pin home: %w", err)
	}
	if parent == "." {
		return current, nil
	}
	for _, component := range strings.Split(parent, string(filepath.Separator)) {
		info, err := current.Lstat(component)
		if err != nil || info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
			_ = current.Close()
			if errors.Is(err, os.ErrPermission) {
				return nil, fmt.Errorf("secure user file: pin parent %q: %w", parent, err)
			}
			return nil, fmt.Errorf("secure user file: invalid parent %q: %w", parent, ErrTargetUnusable)
		}
		next, handle, err := f.home.pinDirectory(current, component)
		if err != nil {
			_ = current.Close()
			return nil, err
		}
		if err := f.home.VerifyOwner(handle, component); err != nil {
			_ = handle.Close()
			_ = next.Close()
			_ = current.Close()
			return nil, err
		}
		_ = handle.Close()
		_ = current.Close()
		current = next
	}
	return current, nil
}

func isAbsSymlinkTarget(target string) bool {
	if target == "" {
		return false
	}
	return target[0] == '/' || target[0] == filepath.Separator || filepath.IsAbs(target)
}

func endsInSeparatorOrDot(target string) bool {
	if target == "" {
		return false
	}
	last := target[len(target)-1]
	if last == '/' || last == filepath.Separator {
		return true
	}
	return target == "." || strings.HasSuffix(target, "/.") ||
		(filepath.Separator != '/' && strings.HasSuffix(target, string(filepath.Separator)+"."))
}

func (f *File) Read() ([]byte, bool, os.FileMode, error) {
	rt, err := f.resolveLeaf()
	if err != nil {
		return nil, false, 0, err
	}
	defer rt.close()
	return f.readCurrent(rt)
}

// MetadataSecure verifies the current leaf's platform permission boundary.
func (f *File) MetadataSecure(want os.FileMode) (bool, error) {
	file, err := f.openMetadata()
	if err != nil || file == nil {
		return false, err
	}
	defer file.Close()
	return f.home.metadata.secure(file, f.home, want)
}

func (f *File) openMetadata() (*os.File, error) {
	rt, err := f.resolveLeaf()
	if err != nil {
		return nil, err
	}
	defer rt.close()
	li, err := rt.child.Lstat(rt.base)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || li.Mode()&fs.ModeSymlink != 0 || !li.Mode().IsRegular() {
		return nil, fmt.Errorf("secure user file: invalid leaf metadata: %w", ErrTargetUnusable)
	}
	file, err := rt.child.OpenFile(rt.base, os.O_RDONLY|nonblockOpenFlag(), 0)
	if err != nil {
		return nil, fmt.Errorf("secure user file: open leaf metadata: %w", err)
	}
	hi, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure user file: stat leaf metadata: %w", err)
	}
	li2, err := rt.child.Lstat(rt.base)
	if err != nil || li2.Mode()&fs.ModeSymlink != 0 || !os.SameFile(li2, hi) {
		_ = file.Close()
		return nil, fmt.Errorf("secure user file: leaf changed during metadata check: %w", ErrTargetUnusable)
	}
	if err := f.home.VerifyOwner(file, rt.base); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func (f *File) readCurrent(rt *secureResolvedTarget) ([]byte, bool, os.FileMode, error) {
	li, err := rt.child.Lstat(rt.base)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, 0, nil
	}
	if err != nil {
		return nil, false, 0, fmt.Errorf("secure user file: lstat leaf %q: %w", rt.base, err)
	}
	if li.Mode()&fs.ModeSymlink != 0 || !li.Mode().IsRegular() {
		return nil, false, 0, fmt.Errorf("secure user file: leaf %q is not a regular file: %w", rt.base, ErrTargetUnusable)
	}
	file, err := rt.child.OpenFile(rt.base, os.O_RDONLY|nonblockOpenFlag(), 0)
	if err != nil {
		return nil, false, 0, fmt.Errorf("secure user file: open leaf %q: %w", rt.base, err)
	}
	defer file.Close()
	hi, err := file.Stat()
	if err != nil {
		return nil, false, 0, fmt.Errorf("secure user file: stat leaf handle: %w", err)
	}
	li2, err := rt.child.Lstat(rt.base)
	if err != nil || li2.Mode()&fs.ModeSymlink != 0 || !hi.Mode().IsRegular() || !li2.Mode().IsRegular() || !os.SameFile(li2, hi) {
		return nil, false, 0, fmt.Errorf("secure user file: leaf %q changed during open: %w", rt.base, ErrTargetUnusable)
	}
	if err := f.home.VerifyOwner(file, rt.base); err != nil {
		return nil, false, 0, err
	}
	data, err := io.ReadAll(io.LimitReader(file, f.maxBytes+1))
	if err != nil {
		return nil, false, 0, fmt.Errorf("secure user file: read leaf %q: %w", rt.base, err)
	}
	if int64(len(data)) > f.maxBytes {
		return nil, false, 0, fmt.Errorf("secure user file: leaf %q exceeds %d bytes: %w", rt.base, f.maxBytes, ErrTargetUnusable)
	}
	return data, true, hi.Mode().Perm(), nil
}

func (f *File) Commit(data []byte, mode os.FileMode) error {
	if mode.Perm()&^os.FileMode(0o600) != 0 {
		return fmt.Errorf("secure user file: file mode must be no broader than 0600: %w", ErrTargetUnusable)
	}
	if int64(len(data)) > f.maxBytes {
		return fmt.Errorf("secure user file: new content exceeds %d bytes: %w", f.maxBytes, ErrTargetUnusable)
	}
	rt, err := f.resolveLeaf()
	if err != nil {
		return err
	}
	defer rt.close()
	current, existed, oldMode, err := f.readCurrent(rt)
	if err != nil {
		return err
	}
	if !existed {
		oldMode = mode
	}
	snap := &secureFileSnapshot{data: current, existed: existed, mode: oldMode, leaf: rt.rel}
	if existed {
		if err := f.backup(rt, current); err != nil {
			f.log("secure user file: backup of %q failed: %v", rt.base, err)
		}
	}
	out, err := f.commit(rt, data, mode)
	if err != nil {
		if out.renamed {
			return f.afterFailedRollback(rt, snap, err)
		}
		return err
	}
	snap.committed = out.committed
	readback, exists, _, err := f.readCurrent(rt)
	if err != nil || !exists || !bytes.Equal(readback, data) {
		if err == nil {
			err = errors.New("secure user file: committed bytes did not match readback")
		}
		return f.afterFailedRollback(rt, snap, err)
	}
	f.pending = snap
	return nil
}

func (f *File) Remove() error {
	rt, err := f.resolveLeaf()
	if err != nil {
		return err
	}
	defer rt.close()
	current, existed, mode, err := f.readCurrent(rt)
	if err != nil {
		return err
	}
	if !existed {
		f.pending = &secureFileSnapshot{leaf: rt.rel}
		return nil
	}
	snap := &secureFileSnapshot{data: current, existed: true, mode: mode, leaf: rt.rel}
	if err := f.backup(rt, current); err != nil {
		f.log("secure user file: backup of %q failed: %v", rt.base, err)
	}
	info, err := rt.child.Lstat(rt.base)
	if err != nil {
		return fmt.Errorf("secure user file: lstat before remove: %w", err)
	}
	if err := rt.child.Remove(rt.base); err != nil {
		return fmt.Errorf("secure user file: remove %q: %w", rt.base, err)
	}
	snap.committed = info
	snap.removed = true
	f.pending = snap
	f.syncDir(rt)
	return nil
}

func (f *File) RestoreSnapshot() error {
	if f.pending == nil {
		return errors.New("secure user file: no snapshot to restore")
	}
	snap := f.pending
	f.pending = nil
	var rt *secureResolvedTarget
	var err error
	if snap.removed {
		var rel string
		rel, err = f.resolveLeafPath(true)
		if err == nil && rel != snap.leaf {
			err = fmt.Errorf("secure user file: chain moved from %q to %q: %w", snap.leaf, rel, ErrTargetUnusable)
		}
		if err == nil {
			rt, err = f.pin(snap.leaf)
		}
		if err == nil {
			if _, lerr := rt.child.Lstat(rt.base); !errors.Is(lerr, os.ErrNotExist) {
				if lerr != nil {
					err = fmt.Errorf("secure user file: inspect removed leaf before restore: %w", lerr)
				} else {
					err = fmt.Errorf("secure user file: removed leaf was recreated: %w", ErrTargetUnusable)
				}
			}
		}
	} else {
		rt, err = f.resolveLeaf()
		if err == nil && rt.rel != snap.leaf {
			err = fmt.Errorf("secure user file: chain moved from %q to %q: %w", snap.leaf, rt.rel, ErrTargetUnusable)
		}
	}
	if err != nil {
		if rt != nil {
			rt.close()
		}
		return err
	}
	defer rt.close()
	if snap.committed != nil {
		li, err := rt.child.Lstat(rt.base)
		if err == nil && (li.Mode()&fs.ModeSymlink != 0 || !li.Mode().IsRegular() || !os.SameFile(li, snap.committed)) {
			return fmt.Errorf("secure user file: leaf changed since commit: %w", ErrTargetUnusable)
		}
		if err != nil && !(errors.Is(err, os.ErrNotExist) && (!snap.existed || snap.removed)) {
			return fmt.Errorf("secure user file: inspect before restore: %w", err)
		}
	}
	return f.restoreFrom(rt, snap)
}

func (f *File) restoreFrom(rt *secureResolvedTarget, snap *secureFileSnapshot) error {
	if !snap.existed {
		if err := rt.child.Remove(rt.base); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("secure user file: restore remove: %w", err)
		}
		return nil
	}
	_, err := f.commit(rt, snap.data, snap.mode)
	return err
}

func (f *File) afterFailedRollback(rt *secureResolvedTarget, snap *secureFileSnapshot, cause error) error {
	if err := f.restoreFrom(rt, snap); err != nil {
		f.log("secure user file: rollback failed: %v", err)
		return fmt.Errorf("secure user file: %v: %w", cause, ErrWriteUnverified)
	}
	return cause
}

type secureCommitOutcome struct {
	committed os.FileInfo
	renamed   bool
}

func (f *File) commit(rt *secureResolvedTarget, data []byte, mode os.FileMode) (secureCommitOutcome, error) {
	tmp, tmpName, err := f.createExclusive(rt, rt.base+".dmg-tmp-", "")
	if err != nil {
		return secureCommitOutcome{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = rt.child.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return secureCommitOutcome{}, fmt.Errorf("secure user file: write temp: %w", err)
	}
	if err := f.applyMetadata(tmp, mode, false); err != nil {
		_ = tmp.Close()
		return secureCommitOutcome{}, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return secureCommitOutcome{}, fmt.Errorf("secure user file: sync temp: %w", err)
	}
	tmpInfo, err := tmp.Stat()
	if err != nil {
		_ = tmp.Close()
		return secureCommitOutcome{}, fmt.Errorf("secure user file: stat temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return secureCommitOutcome{}, fmt.Errorf("secure user file: close temp: %w", err)
	}
	if err := rt.child.Rename(tmpName, rt.base); err != nil {
		return secureCommitOutcome{}, fmt.Errorf("secure user file: rename into place: %w", err)
	}
	cleanup = false
	li, err := rt.child.Lstat(rt.base)
	if err != nil {
		return secureCommitOutcome{renamed: true}, fmt.Errorf("secure user file: lstat after rename: %w", err)
	}
	if li.Mode()&fs.ModeSymlink != 0 || !li.Mode().IsRegular() || !os.SameFile(li, tmpInfo) {
		return secureCommitOutcome{renamed: true}, fmt.Errorf("secure user file: identity changed across rename: %w", ErrTargetUnusable)
	}
	f.syncDir(rt)
	return secureCommitOutcome{committed: li, renamed: true}, nil
}

func (f *File) createExclusive(rt *secureResolvedTarget, prefix, suffix string) (*os.File, string, error) {
	for range 8 {
		middle, err := f.home.randomSuffix()
		if err != nil {
			return nil, "", fmt.Errorf("secure user file: random suffix: %w", err)
		}
		name := prefix + middle + suffix
		file, err := rt.child.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, FileMode)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("secure user file: create %q: %w", name, err)
		}
		return file, name, nil
	}
	return nil, "", errors.New("secure user file: could not create a unique temporary file")
}

func (f *File) syncDir(rt *secureResolvedTarget) {
	dir, err := rt.child.Open(".")
	if err != nil {
		return
	}
	_ = dir.Sync()
	_ = dir.Close()
}

func (f *File) backup(rt *secureResolvedTarget, data []byte) error {
	file, name, err := f.createExclusive(rt, rt.base+f.backupPrefix, ".bak")
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = rt.child.Remove(name)
		return fmt.Errorf("secure user file: write backup: %w", err)
	}
	if err := f.applyMetadata(file, FileMode, false); err != nil {
		_ = file.Close()
		_ = rt.child.Remove(name)
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("secure user file: close backup: %w", err)
	}
	f.rotateBackups(rt)
	return nil
}

func (f *File) rotateBackups(rt *secureResolvedTarget) {
	dir, err := rt.child.Open(".")
	if err != nil {
		f.log("secure user file: backup rotation open failed: %v", err)
		return
	}
	defer dir.Close()
	prefix := rt.base + f.backupPrefix
	tmpPrefix := rt.base + ".dmg-tmp-"
	type backupFile struct {
		name  string
		mtime int64
	}
	kept := make([]backupFile, 0, maxBackups)
	insert := func(item backupFile) {
		i := sort.Search(len(kept), func(i int) bool { return kept[i].mtime > item.mtime })
		kept = append(kept, backupFile{})
		copy(kept[i+1:], kept[i:])
		kept[i] = item
	}
	remove := func(name string) {
		if err := rt.child.Remove(name); err != nil {
			f.log("secure user file: prune backup %q failed: %v", name, err)
		}
	}
	for {
		entries, readErr := dir.ReadDir(256)
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".bak") || strings.HasPrefix(name, tmpPrefix) {
				continue
			}
			info, err := rt.child.Lstat(name)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			item := backupFile{name: name, mtime: info.ModTime().UnixNano()}
			if len(kept) < maxBackups {
				insert(item)
			} else if item.mtime <= kept[0].mtime {
				remove(item.name)
			} else {
				remove(kept[0].name)
				copy(kept, kept[1:])
				kept = kept[:len(kept)-1]
				insert(item)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return
		}
		if readErr != nil {
			f.log("secure user file: backup rotation read failed: %v", readErr)
			return
		}
	}
}

func (f *File) PurgeBackups() error {
	var rt *secureResolvedTarget
	var err error
	if f.pending != nil && f.pending.leaf != "" {
		rt, err = f.pin(f.pending.leaf)
	} else {
		rt, err = f.resolveLeaf()
	}
	if err != nil {
		return err
	}
	defer rt.close()
	return f.purgeBackups(rt)
}

func (f *File) purgeBackups(rt *secureResolvedTarget) error {
	dir, err := rt.child.Open(".")
	if err != nil {
		return fmt.Errorf("secure user file: open parent for backup purge: %w", err)
	}
	defer dir.Close()
	prefix := rt.base + f.backupPrefix
	tmpPrefix := rt.base + ".dmg-tmp-"
	var firstErr error
	for {
		entries, readErr := dir.ReadDir(256)
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".bak") || strings.HasPrefix(name, tmpPrefix) {
				continue
			}
			info, err := rt.child.Lstat(name)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if err := rt.child.Remove(name); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return firstErr
		}
		if readErr != nil {
			if firstErr != nil {
				return firstErr
			}
			return readErr
		}
	}
}

func randomSuffix() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
