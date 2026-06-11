package devmdm

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Reconciler converges the OS-native VS Code policy to the backend's effective
// policy for one device, once per scheduled cycle. It is OS-agnostic: the
// per-OS Writer, the policy Fetcher, the compliance Reporter, and VS Code
// version detection are all injected, so the whole flow is fake-testable with
// no real I/O.
type Reconciler struct {
	Fetcher  Fetcher
	Reporter Reporter
	// Writer is the per-OS native-policy writer, or nil when the platform is not
	// agent-enforceable (macOS / other). A nil Writer makes Reconcile a no-op.
	Writer Writer

	CustomerID string
	DeviceID   string
	Platform   string // reported in compliance; e.g. "windows", "linux"
	Category   string // defaults to ide_extension

	// VSCodeVersion returns the installed VS Code version (e.g. "1.96.2") or ""
	// when VS Code is absent/undetectable. "" compares below every floor and
	// yields vscode_unsupported.
	VSCodeVersion func() string

	// Now and Logf are optional seams. Now defaults to time.Now().UTC; Logf to a
	// no-op.
	Now  func() time.Time
	Logf func(format string, args ...any)

	// writeState is a test seam over WriteAppliedState (the ownership store).
	// nil → the real implementation.
	writeState func(AppliedState) error
}

func (r *Reconciler) persistState(s AppliedState) error {
	if r.writeState != nil {
		return r.writeState(s)
	}
	return WriteAppliedState(s)
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}

func (r *Reconciler) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

func (r *Reconciler) category() string {
	if r.Category != "" {
		return r.Category
	}
	return CategoryIDEExtension
}

func (r *Reconciler) vscodeVersion() string {
	if r.VSCodeVersion == nil {
		return ""
	}
	return r.VSCodeVersion()
}

// Reconcile runs one enforcement cycle. It NEVER panics into the caller's hot
// path; failures are returned for logging. The contract:
//
//   - fetch error (transport / non-200 / malformed) → NO-OP, error returned.
//     Enforcement on disk is never wiped on a transient or malformed response.
//   - platform not enforceable (nil Writer) → silent no-op.
//   - clear result → clear ONLY the agent-owned policy; a foreign value is left
//     untouched. No compliance report (an unassigned device is backend-derived).
//   - policy result → ownership-checked write + readback + verify + report.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	if r.Fetcher == nil {
		return errors.New("devmdm: nil fetcher")
	}
	cat := r.category()

	ep, err := r.Fetcher.Fetch(ctx, r.CustomerID, r.DeviceID, cat)
	if err != nil {
		// Malformed/transient: do nothing. The on-disk policy (if any) stands.
		return fmt.Errorf("devmdm: fetch: %w", err)
	}

	if r.Writer == nil {
		// macOS / unsupported platform: the backend gates these to clear and
		// delivers via MDM export. Nothing to do, nothing to report.
		r.logf("devmdm: platform not agent-enforceable; skipping (category=%s)", cat)
		return nil
	}

	if ep.Clear {
		return r.handleClear(cat)
	}
	return r.handleEnforce(ctx, cat, ep)
}

// handleClear removes the agent-owned policy on unassignment. It clears the
// on-disk value ONLY when it still equals what the agent last wrote (ownership);
// a foreign value (MDM/human) is left intact.
func (r *Reconciler) handleClear(cat string) error {
	prev, _ := ReadAppliedState()
	onDisk, present, err := r.Writer.Read()
	if err != nil {
		return fmt.Errorf("devmdm: clear: read %s: %w", r.Writer.Location(), err)
	}

	owns := present && prev.WrittenValue != "" && onDisk == prev.WrittenValue
	switch {
	case owns:
		if err := r.Writer.Clear(); err != nil {
			return fmt.Errorf("devmdm: clear %s: %w", r.Writer.Location(), err)
		}
		r.logf("devmdm: cleared agent-owned policy at %s", r.Writer.Location())
	case present:
		// A value the agent does not own — leave it for the MDM/human that set it.
		r.logf("devmdm: clear requested but %s holds a foreign value; leaving it", r.Writer.Location())
	}

	// Drop our ownership record (only when we had one, to stay idempotent).
	if prev.WrittenValue != "" || prev.AppliedHash != "" {
		if err := r.persistState(AppliedState{Category: cat, FetchedAt: r.now()}); err != nil {
			return fmt.Errorf("devmdm: clear: update state: %w", err)
		}
	}
	return nil
}

// handleEnforce writes the compiled policy (ownership-safe), reads it back,
// verifies, and reports. The decision order matches the PRD: version floor →
// ownership → write/readback.
func (r *Reconciler) handleEnforce(ctx context.Context, cat string, ep EffectivePolicy) error {
	newValue := string(ep.Policy)
	version := r.vscodeVersion()

	// 1. Version floor. Below it (or VS Code absent/unknown), the policy can't be
	// honored — report vscode_unsupported and do not touch the box.
	if !versionAtLeast(version, ep.MinVSCodeVersion) {
		state := Verify(VerifyInput{VSCodeVersion: version, MinVSCodeVersion: ep.MinVSCodeVersion})
		r.logf("devmdm: vscode %q below floor %q → %s", version, ep.MinVSCodeVersion, state)
		return r.report(ctx, cat, state, "")
	}

	// 2. Ownership. Read current value to decide whether we may write.
	prev, hadPrev := ReadAppliedState()
	onDisk, present, err := r.Writer.Read()
	if err != nil {
		// Couldn't read to decide ownership/readback → verification_failed.
		_ = r.report(ctx, cat, StateVerificationFailed, "")
		return fmt.Errorf("devmdm: enforce: read %s: %w", r.Writer.Location(), err)
	}
	// A present value is foreign unless the agent has a record of writing
	// exactly it. No record (prev.WrittenValue == "") means ANY present value —
	// including one byte-equal to the desired policy, or a writer's
	// "present but not a representable string" result (e.g. a wrong-typed
	// registry value) — is MDM/human-owned: yield, never overwrite.
	foreign := present && (prev.WrittenValue == "" || onDisk != prev.WrittenValue)
	if foreign {
		r.logf("devmdm: %s holds a foreign value → mdm_managed (yielding)", r.Writer.Location())
		return r.report(ctx, cat, StateMDMManaged, "")
	}

	// 3. Write (unless already converged) + readback.
	var writeOK, readbackMatch bool
	switch {
	case present && onDisk == newValue && prev.AppliedHash == ep.Hash:
		// Idempotent: the desired policy is already in place and unchanged. No
		// write — but still report so the backend sees a fresh evaluation.
		writeOK, readbackMatch = true, true
		r.logf("devmdm: policy already applied (hash unchanged) — no write")
	default:
		// Preflight: prove the ownership store is writable BEFORE mutating the
		// policy location. An enforced value with no ownership record is orphaned
		// — a later clear refuses to remove it and the agent misreports its own
		// write as mdm_managed. Re-persisting the current state is a
		// meaning-preserving writability probe.
		probe := prev
		if !hadPrev {
			probe = AppliedState{Category: cat, FetchedAt: r.now()}
		}
		if perr := r.persistState(probe); perr != nil {
			_ = r.report(ctx, cat, StateWriteFailed, "")
			return fmt.Errorf("devmdm: enforce: ownership state not writable, refusing to write policy: %w", perr)
		}

		rb, werr := r.Writer.Write(newValue)
		if werr != nil {
			_ = r.report(ctx, cat, StateWriteFailed, "")
			return fmt.Errorf("devmdm: enforce: write %s: %w", r.Writer.Location(), werr)
		}
		writeOK = true
		readbackMatch = rb == newValue
		// Ownership is recorded on EVERY successful write — it means "what the
		// agent wrote", not "what it verified". On a readback mismatch (e.g. a
		// transient race) the write may still have landed; without a record the
		// next cycle would classify the agent's own value as foreign and stick
		// at mdm_managed. Value-based ownership self-corrects: the record only
		// takes effect when the on-disk value actually equals it.
		if err := r.persistState(AppliedState{
			Category:     cat,
			AppliedHash:  ep.Hash,
			WrittenValue: newValue,
			FetchedAt:    r.now(),
		}); err != nil {
			// The write happened but ownership couldn't be recorded — undo it so
			// no unrecorded value is left behind, and report a failed write.
			r.rollbackWrite(onDisk, present)
			_ = r.report(ctx, cat, StateWriteFailed, "")
			return fmt.Errorf("devmdm: enforce: update state: %w", err)
		}
		r.logf("devmdm: wrote policy to %s (readback_match=%v)", r.Writer.Location(), readbackMatch)
	}

	state := Verify(VerifyInput{
		WriteOK:          writeOK,
		ReadbackMatch:    readbackMatch,
		VSCodeVersion:    version,
		MinVSCodeVersion: ep.MinVSCodeVersion,
	})

	// applied_hash is echoed only when we are confident the policy is applied
	// (readback-confirmed). It is the backend's hash verbatim — never recomputed —
	// so the backend's byte-exact applied==desired check gates `compliant`.
	appliedHash := ""
	if state == StateCompliant {
		appliedHash = ep.Hash
	}
	return r.report(ctx, cat, state, appliedHash)
}

// rollbackWrite restores the policy location to its pre-cycle condition after
// the post-write ownership persist failed. WriteAppliedState is atomic
// (temp+rename), so the failed persist left the previous state file intact —
// restoring the previous on-disk value keeps record and disk consistent.
// Best-effort: a rollback failure is logged, and the orphaned value surfaces
// as mdm_managed on the next cycle.
func (r *Reconciler) rollbackWrite(prevOnDisk string, prevPresent bool) {
	var err error
	if prevPresent {
		_, err = r.Writer.Write(prevOnDisk)
	} else {
		err = r.Writer.Clear()
	}
	if err != nil {
		r.logf("devmdm: rollback at %s failed: %v", r.Writer.Location(), err)
	}
}

func (r *Reconciler) report(ctx context.Context, cat, state, appliedHash string) error {
	r.logf("devmdm: reporting state=%s category=%s", state, cat)
	if r.Reporter == nil {
		return nil
	}
	rep := ComplianceReport{
		Category:     cat,
		State:        state,
		AppliedHash:  appliedHash,
		AgentVersion: AgentVersion(),
		Platform:     r.Platform,
	}
	if err := r.Reporter.Report(ctx, r.CustomerID, r.DeviceID, rep); err != nil {
		return fmt.Errorf("devmdm: report %s: %w", state, err)
	}
	return nil
}
