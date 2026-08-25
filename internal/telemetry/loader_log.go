package telemetry

import (
	"io"
	"os"
	"path/filepath"

	"github.com/step-security/dev-machine-guard/internal/paths"
)

// loaderLogFilename is the dedicated file the loader scripts append THIS run's
// own output to (their print_info / print_error / print_success helpers write to
// it), so the binary can fold the loader's lines into its run-status logs. It
// lives in the install dir alongside agent.error.log. Unlike agent.error.log it
// carries ONLY the loader's lines (not the binary's), is written by the loader
// regardless of how it was launched (so it survives an admin/MDM install where
// stderr isn't scheduler-redirected), and the binary deletes it after reading
// (see seedLoaderLog) — so it is naturally scoped to the current run.
const loaderLogFilename = ".loader_log"

// loaderLogReadBytes caps how much of .loader_log we fold in. The loader
// truncates the file fresh at the start of each run, so it only ever holds one
// run's (small) output; this is a defensive bound on that read.
const loaderLogReadBytes = 64 * 1024

// seedLoaderLog folds the loader script's lines for THIS run (binary
// auto-update, config write, version checks — and, on a first install, the
// "downloading…/installed…/config written" lines) into the capture, so the
// run-status log tail and the downloadable ExecutionLogs carry them under the
// SAME run-status row as the binary's own output. The loader truncates
// .loader_log fresh at the start of the run and writes its lines there before
// handing off to this binary; we read that file, seed it, and then DELETE it.
// Truncate-on-write bounds the file even if no binary consumes it, and delete
// scopes the content to this run so a later run can't re-fold stale lines.
//
// Best-effort: an unresolved install dir, or a missing/unreadable file, is a
// no-op. The file is simply absent when the binary is run directly, or on a
// platform whose loader doesn't write it.
func seedLoaderLog(capture *LogCapture) {
	if capture == nil {
		return
	}
	home := paths.Home()
	if home == "" {
		return
	}
	path := filepath.Join(home, loaderLogFilename)
	// Consume the file regardless of read outcome: it's this run's loader output,
	// folded in below (or unreadable), so it must not linger into a later run.
	// Best-effort — a failed remove just means the next run folds it in + retries.
	defer func() { _ = os.Remove(path) }()

	raw, err := tailFile(path, loaderLogReadBytes)
	if err != nil || len(raw) == 0 {
		return
	}
	capture.Seed([]byte("----- loader script log -----\n"))
	capture.Seed(raw)
	capture.Seed([]byte("\n----- end loader script log -----\n"))
}

// tailFile returns up to the last n bytes of the file at path (all of it when
// the file is smaller). Bounds how much we read without loading a potentially
// large (orphaned) file in full.
func tailFile(path string, n int) ([]byte, error) {
	f, err := os.Open(path) //#nosec G304 -- path is the agent's own .loader_log under the resolved install dir.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() == 0 {
		return nil, nil
	}
	off := int64(0)
	if st.Size() > int64(n) {
		off = st.Size() - int64(n)
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}
