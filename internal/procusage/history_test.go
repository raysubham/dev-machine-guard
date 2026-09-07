package procusage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testRecord(id string) Record {
	return Record{
		Timestamp:    time.Unix(1_700_000_000, 0).UTC(),
		AgentVersion: "1.16.0",
		Command:      "scan",
		OS:           "linux",
		ExecutionID:  id,
		Usage:        Sample{WallMs: 1000, CPUUserMs: 400, ChildrenAttributed: true},
	}
}

func TestAppendHistoryEmptyPathIsNoOp(t *testing.T) {
	if err := AppendHistory("", testRecord("x")); err != nil {
		t.Errorf("AppendHistory(\"\") = %v, want nil", err)
	}
}

func TestAppendHistoryRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run-metrics.jsonl")

	for _, id := range []string{"a", "b", "c"} {
		if err := AppendHistory(path, testRecord(id)); err != nil {
			t.Fatalf("AppendHistory(%s) = %v", id, err)
		}
	}

	got, err := LoadHistory(path)
	if err != nil {
		t.Fatalf("LoadHistory: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("records = %d, want 3", len(got))
	}
	for i, want := range []string{"a", "b", "c"} {
		if got[i].ExecutionID != want {
			t.Errorf("record %d id = %q, want %q (append order not preserved)", i, got[i].ExecutionID, want)
		}
	}
	if got[0].Usage.CPUUserMs != 400 {
		t.Errorf("cpu_user_ms = %d, want 400", got[0].Usage.CPUUserMs)
	}
}

func TestAppendHistoryCreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "run-metrics.jsonl")
	if err := AppendHistory(path, testRecord("a")); err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func TestAppendHistoryTrimsToCapKeepingNewest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run-metrics.jsonl")

	total := maxHistoryRecords + 25
	for i := range total {
		if err := AppendHistory(path, testRecord(fmt.Sprintf("run-%03d", i))); err != nil {
			t.Fatalf("AppendHistory(%d) = %v", i, err)
		}
	}

	got, err := LoadHistory(path)
	if err != nil {
		t.Fatalf("LoadHistory: %v", err)
	}
	if len(got) != maxHistoryRecords {
		t.Fatalf("records = %d, want %d", len(got), maxHistoryRecords)
	}
	// The oldest 25 should have aged out, not the newest.
	wantFirst := fmt.Sprintf("run-%03d", total-maxHistoryRecords)
	if got[0].ExecutionID != wantFirst {
		t.Errorf("first record = %q, want %q", got[0].ExecutionID, wantFirst)
	}
	wantLast := fmt.Sprintf("run-%03d", total-1)
	if got[len(got)-1].ExecutionID != wantLast {
		t.Errorf("last record = %q, want %q", got[len(got)-1].ExecutionID, wantLast)
	}
}

func TestLoadHistorySkipsUnparseableLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run-metrics.jsonl")
	good, err := json.Marshal(testRecord("good"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// A truncated write in the middle must not hide the rest of the file.
	content := strings.Join([]string{
		string(good),
		`{"ts":"2026-09-07T00:00:0`,
		"",
		"not json at all",
		string(good),
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	got, err := LoadHistory(path)
	if err != nil {
		t.Fatalf("LoadHistory: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("records = %d, want 2 parseable", len(got))
	}
}

func TestLoadHistoryMissingFile(t *testing.T) {
	got, err := LoadHistory(filepath.Join(t.TempDir(), "absent.jsonl"))
	if err != nil {
		t.Errorf("LoadHistory on missing file = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("records = %v, want nil", got)
	}
}

// TestChildrenAttributedAlwaysSerialized guards the one field that must
// not be omitempty: a Windows record with the flag absent is
// indistinguishable from a Unix run that spawned no subprocesses.
func TestChildrenAttributedAlwaysSerialized(t *testing.T) {
	b, err := json.Marshal(Sample{WallMs: 1, ChildrenAttributed: false})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"children_attributed":false`) {
		t.Errorf("marshalled sample = %s, want children_attributed present and false", b)
	}
}

func TestAppendHistoryUnwritablePathErrors(t *testing.T) {
	// A file where a directory needs to be: MkdirAll must fail rather
	// than the caller silently losing history.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	err := AppendHistory(filepath.Join(blocker, "run-metrics.jsonl"), testRecord("a"))
	if err == nil {
		t.Error("AppendHistory into a non-directory = nil, want error")
	}
}
