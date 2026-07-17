package telemetry

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestLogCaptureSyncFlushesRecentWrites drives real writes through StartCapture
// (os.Stderr -> pipe -> async tee -> ring), NOT ring.Write directly, and asserts
// that Sync() makes the most-recently-written line visible to SnapshotBase64.
//
// This is the case that regressed: on a fast run the tee has not yet copied the
// final line into the ring when the snapshot is taken, so the downloadable log
// cut off early. Sync() must guarantee that line is present. It also asserts the
// in-band sync marker never leaks into the captured output.
func TestLogCaptureSyncFlushesRecentWrites(t *testing.T) {
	lc := StartCapture()
	defer lc.Finalize()

	fmt.Fprintln(os.Stderr, "line one")
	const last = "Uploading telemetry to S3 (70583 bytes)..."
	fmt.Fprint(os.Stderr, last)

	lc.Sync()

	decoded, err := base64.StdEncoding.DecodeString(lc.SnapshotBase64())
	if err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	got := string(decoded)
	if !strings.Contains(got, last) {
		t.Errorf("snapshot after Sync() is missing the final line\n want substring: %q\n got: %q", last, got)
	}
	if strings.Contains(got, "STEPSEC_LOGCAPTURE_SYNC") {
		t.Errorf("sync marker leaked into captured output: %q", got)
	}
}

// TestLogCaptureFinalizeReturnsAllWithoutSync guards that the marker-stripping
// tee (which holds back a partial-marker tail between reads) still flushes that
// tail on Finalize, so a run that never calls Sync loses no output.
func TestLogCaptureFinalizeReturnsAllWithoutSync(t *testing.T) {
	lc := StartCapture()
	const msg = "alpha beta gamma delta epsilon"
	fmt.Fprint(os.Stderr, msg)

	decoded, err := base64.StdEncoding.DecodeString(lc.Finalize())
	if err != nil {
		t.Fatalf("decode finalize: %v", err)
	}
	if !strings.Contains(string(decoded), msg) {
		t.Errorf("Finalize dropped trailing output\n want substring: %q\n got: %q", msg, decoded)
	}
}
