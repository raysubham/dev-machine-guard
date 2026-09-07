//go:build darwin || linux

package configaudit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestPipConfigMetadataRejectsFIFOWithoutOpening(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "pip.conf")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{fifo, filepath.Join(t.TempDir(), "pip.conf")} {
		if path != fifo {
			if err := os.Symlink(fifo, path); err != nil {
				t.Fatal(err)
			}
		}
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			d := NewPipConfigDetector(executor.NewMock())
			file := model.PipConfigFile{Path: path}
			done := make(chan struct{})
			go func() {
				d.populateFileMetadata(context.Background(), &file)
				close(done)
			}()

			select {
			case <-done:
				if !strings.Contains(file.ParseError, "not a regular file") {
					t.Fatalf("ParseError = %q, want non-regular refusal", file.ParseError)
				}
			case <-time.After(250 * time.Millisecond):
				writer, _ := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0)
				if writer != nil {
					_ = writer.Close()
				}
				t.Fatal("populateFileMetadata blocked opening a FIFO")
			}
		})
	}
}
