//go:build windows

package devicepolicy

import "os"

const enforcePOSIXMetadata = false

func nonblockOpenFlag() int { return 0 }

func chownHandle(*os.File, int, int) error { return nil }

func newOwnerReader() ownerReader { return windowsOwnerReader{} }

type windowsOwnerReader struct{}

func (windowsOwnerReader) ownerUIDGID(*os.File) (uid, gid uint32, enforced bool, err error) {
	return 0, 0, false, nil
}
