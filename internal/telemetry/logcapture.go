package telemetry

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// captureRingCapacity bounds the in-memory log buffer. Older bytes are
// discarded on overflow. Sized to keep memory usage trivial on multi-hour
// stuck runs while still preserving enough recent context for diagnosis:
// 1 MB ≈ several thousand lines of typical agent output.
const captureRingCapacity = 1 << 20 // 1 MB

// captureSyncMarker is a unique in-band sentinel that Sync() writes to the
// capture pipe to learn the tee goroutine has drained every byte written before
// it. The tee strips it, so it is never stored in the ring or echoed to stderr.
// The NUL/RS control bytes make an accidental match in real log text effectively
// impossible.
const captureSyncMarker = "\x00\x1eSTEPSEC_LOGCAPTURE_SYNC\x1e\x00"

// captureSyncTimeout bounds Sync() so a dead or absent tee goroutine can never
// wedge the caller.
const captureSyncTimeout = 2 * time.Second

// LogCapture captures all stderr output during telemetry execution into a
// bounded ring buffer. The buffer's contents are exposed two ways:
//
//   - Tail(n): the last n bytes, used by heartbeat posts to ship a fresh
//     diagnostic slice on every progress upsert.
//   - Finalize(): the entire current buffer, base64-encoded, embedded in
//     the final ExecutionLogs payload.
//
// Behavior change vs. previous unbounded bytes.Buffer: when a run produces
// more than captureRingCapacity bytes of log output (hours-long stuck
// runs, mainly), the OLDEST bytes are dropped and the final payload
// reflects only the most recent ~1 MB. That's a deliberate trade — the
// oldest output is rarely diagnostic for a hang, and the prior unbounded
// buffer could OOM the agent on a runaway scan.
//
// Nesting with internal/progress/filelog: when filelog is active,
// os.Stderr is already the filelog pipe's write end. StartCapture saves
// that value as origErr, swaps os.Stderr to its own pipe, and on
// Finalize restores os.Stderr = origErr — re-enabling the filelog tee.
// Do not change Finalize to assign os.Stderr to the "real" stderr
// directly; that would orphan filelog mid-run and lose the suffix of
// the log file.
type LogCapture struct {
	ring      *ringBuffer
	mu        sync.Mutex
	origErr   *os.File
	pipeRead  *os.File
	pipeWrite *os.File
	done      chan struct{}
	syncCh    chan struct{} // tee signals here once a Sync() marker is drained
}

// ringBuffer is a fixed-capacity append-only byte sink. Once full, writes
// overwrite the oldest bytes. Safe for single-writer / single-reader; the
// LogCapture mutex enforces that elsewhere.
type ringBuffer struct {
	data  []byte
	start int  // index of the oldest byte when full
	size  int  // current valid byte count (≤ cap(data))
	full  bool // true once size has reached cap(data); start is then meaningful
}

func newRingBuffer(cap int) *ringBuffer { return &ringBuffer{data: make([]byte, cap)} }

func (r *ringBuffer) Write(p []byte) {
	capacity := cap(r.data)
	if capacity == 0 {
		return
	}
	// If the incoming slice is bigger than capacity, keep only the tail —
	// older bytes were going to be overwritten anyway.
	if len(p) > capacity {
		p = p[len(p)-capacity:]
	}
	for _, b := range p {
		if !r.full {
			r.data[r.size] = b
			r.size++
			if r.size == capacity {
				r.full = true
				r.start = 0
			}
			continue
		}
		r.data[r.start] = b
		r.start = (r.start + 1) % capacity
	}
}

// Bytes returns a fresh slice containing all currently buffered bytes in
// write order (oldest first).
func (r *ringBuffer) Bytes() []byte {
	if !r.full {
		out := make([]byte, r.size)
		copy(out, r.data[:r.size])
		return out
	}
	capacity := cap(r.data)
	out := make([]byte, capacity)
	n := copy(out, r.data[r.start:])
	copy(out[n:], r.data[:r.start])
	return out
}

// Tail returns the last n buffered bytes (or all of them if fewer have
// been written). Returns a fresh slice, safe for the caller to retain.
func (r *ringBuffer) Tail(n int) []byte {
	all := r.Bytes()
	if n <= 0 || len(all) == 0 {
		return nil
	}
	if n >= len(all) {
		return all
	}
	return all[len(all)-n:]
}

// StartCapture redirects stderr to a tee that writes to both the original
// stderr and an in-memory ring buffer for later base64 encoding.
func StartCapture() *LogCapture {
	lc := &LogCapture{
		ring:    newRingBuffer(captureRingCapacity),
		origErr: os.Stderr,
		done:    make(chan struct{}),
		syncCh:  make(chan struct{}, 1),
	}

	r, w, err := os.Pipe()
	if err != nil {
		return lc // fallback: no capture
	}
	lc.pipeRead = r
	lc.pipeWrite = w

	// Redirect stderr to the pipe
	os.Stderr = w

	// Tee: read from pipe, write to both original stderr and ring buffer.
	// Sync() markers are detected here, stripped (never teed onward), and
	// acknowledged via syncCh; a carry of marker-1 bytes handles a marker that
	// straddles two reads.
	go func() {
		defer close(lc.done)
		marker := []byte(captureSyncMarker)
		buf := make([]byte, 4096)
		var carry []byte
		for {
			n, err := r.Read(buf)
			if n > 0 {
				data := buf[:n]
				if len(carry) > 0 {
					data = append(carry, data...)
				}
				for {
					i := bytes.Index(data, marker)
					if i < 0 {
						break
					}
					lc.teeWrite(data[:i])
					data = data[i+len(marker):]
					select {
					case lc.syncCh <- struct{}{}:
					default:
					}
				}
				// Hold back a possible partial marker at the tail for the next read.
				if keep := len(marker) - 1; len(data) > keep {
					lc.teeWrite(data[:len(data)-keep])
					carry = append([]byte(nil), data[len(data)-keep:]...)
				} else {
					carry = append([]byte(nil), data...)
				}
			}
			if err != nil {
				lc.teeWrite(carry) // flush any held-back tail before exiting
				break
			}
		}
	}()

	return lc
}

// teeWrite fans a slice out to the ring buffer and the original stderr. Empty
// input is a no-op so the marker-stripping loop can call it unconditionally.
func (lc *LogCapture) teeWrite(p []byte) {
	if len(p) == 0 {
		return
	}
	lc.mu.Lock()
	lc.ring.Write(p)
	lc.mu.Unlock()
	_, _ = lc.origErr.Write(p)
}

// Finalize stops capture and returns the base64-encoded output.
// Safe to call multiple times — subsequent calls return the cached result.
func (lc *LogCapture) Finalize() string {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if lc.pipeWrite == nil {
		// Already finalized or never started
		return base64.StdEncoding.EncodeToString(lc.ringBytesLocked())
	}

	// Close write end so the reader goroutine exits
	_ = lc.pipeWrite.Close()
	lc.pipeWrite = nil
	lc.mu.Unlock()
	<-lc.done
	lc.mu.Lock()

	// Restore stderr
	os.Stderr = lc.origErr
	_ = lc.pipeRead.Close()

	return base64.StdEncoding.EncodeToString(lc.ringBytesLocked())
}

// SnapshotBase64 returns the base64-encoded buffer contents WITHOUT stopping
// capture, so a caller can embed the session-so-far in the telemetry payload
// while the capture keeps recording (e.g. through the upload that follows).
// The real teardown — closing the pipe and restoring os.Stderr — stays in
// Finalize, which the caller still defers. Safe to call during active capture.
func (lc *LogCapture) SnapshotBase64() string {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return base64.StdEncoding.EncodeToString(lc.ringBytesLocked())
}

// Sync blocks until the tee goroutine has drained every byte written to the
// capture pipe before this call — i.e. everything logged so far is now in the
// ring and visible to a following SnapshotBase64/Tail. Unlike Finalize it does
// NOT stop capture: the pipe stays open, so later output (the upload result, the
// completion line) keeps being recorded for the run-status tail. It works by
// writing a unique marker to the pipe and waiting for the tee to read past it,
// which is the only reliable way to flush an asynchronous reader short of
// closing the pipe. Bounded by captureSyncTimeout so an absent or stuck tee
// cannot wedge the caller; on timeout the following snapshot simply reflects
// whatever had drained. No-op before StartCapture or after Finalize.
func (lc *LogCapture) Sync() {
	lc.mu.Lock()
	pw := lc.pipeWrite
	ch := lc.syncCh
	lc.mu.Unlock()
	if pw == nil || ch == nil {
		return
	}
	// Clear any stale ack from a previous Sync so we wait on our own marker.
	select {
	case <-ch:
	default:
	}
	if _, err := pw.WriteString(captureSyncMarker); err != nil {
		return // pipe closed concurrently (Finalize) — nothing left to drain
	}
	select {
	case <-ch:
	case <-time.After(captureSyncTimeout):
	}
}

// Tail returns the last n captured bytes as a fresh slice. Safe to call
// concurrently with active capture; returns nil if the buffer is empty
// or n ≤ 0. Used by heartbeat posts to ship the most recent diagnostic
// slice without bloating the payload.
func (lc *LogCapture) Tail(n int) []byte {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.ring == nil {
		return nil
	}
	return lc.ring.Tail(n)
}

// Seed writes pre-capture bytes directly into the ring buffer WITHOUT echoing
// them to the live stderr / agent.error.log. Used to fold in the loader
// script's earlier agent.log output so heartbeat tails and the final payload
// include it, even though it was logged before StartCapture redirected stderr.
// Call once, right after StartCapture and before any stderr output, so the
// seeded bytes sit at the head of the buffer.
func (lc *LogCapture) Seed(p []byte) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.ring != nil {
		lc.ring.Write(p)
	}
}

func (lc *LogCapture) ringBytesLocked() []byte {
	if lc.ring == nil {
		return nil
	}
	return lc.ring.Bytes()
}

// Write allows direct writing to the capture buffer (for banner etc.)
// while also writing to stderr.
func (lc *LogCapture) Write(p []byte) (n int, err error) {
	if lc.pipeWrite != nil {
		return lc.pipeWrite.Write(p)
	}
	return lc.origErr.Write(p)
}

// Fprintf is a convenience method.
func (lc *LogCapture) Fprintf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	_, _ = io.WriteString(lc, msg)
}
