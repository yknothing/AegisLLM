// Package revocation implements durable single-host virtual-key revocation.
//
// SECURITY PROPERTIES:
//   - The writer serializes processes with a kernel lock and commits snapshots
//     using fsync plus same-directory atomic rename.
//   - The reader strictly validates a bounded, owner-only regular file before
//     atomically publishing an immutable in-memory lookup table.
//   - Missing, corrupt, permission-unsafe, or runtime-observed rollback state
//     fails closed. Cross-restart rollback requires an external trusted anchor.
//   - Snapshots contain only issuer/key identifiers and timestamps, never JWTs.
package revocation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	snapshotVersion     = 1
	maxSnapshotBytes    = 4 << 20
	maxSnapshotEntries  = 100_000
	maxIdentifierBytes  = 1024
	revocationClockSkew = 60 * time.Second
)

var (
	// ErrUnavailable means revocation state cannot currently be trusted.
	ErrUnavailable = errors.New("revocation state unavailable")
	// ErrRollback means a reader observed a generation older than one it had
	// already accepted.
	ErrRollback = errors.New("revocation snapshot generation rollback")
)

type entry struct {
	Issuer      string `json:"issuer"`
	KeyID       string `json:"kid"`
	RevokedAt   int64  `json:"revoked_at"`
	RetainUntil int64  `json:"retain_until"`
}

type snapshot struct {
	Version    int     `json:"version"`
	Generation uint64  `json:"generation"`
	UpdatedAt  int64   `json:"updated_at"`
	Entries    []entry `json:"entries"`
}

// CommitResult describes durable local state after a writer operation.
type CommitResult struct {
	Generation uint64
	UpdatedAt  time.Time
	Changed    bool
}

// Writer updates one local snapshot. It is safe to construct multiple Writer
// values because every mutation takes the same kernel advisory lock.
type Writer struct {
	path        string
	lockTimeout time.Duration
}

// NewWriter creates a local snapshot writer.
func NewWriter(path string, lockTimeout time.Duration) *Writer {
	return &Writer{path: path, lockTimeout: lockTimeout}
}

// Init creates an empty versioned snapshot if none exists. Existing valid
// state is preserved; existing invalid state is never overwritten silently.
func (w *Writer) Init(ctx context.Context, now time.Time) (CommitResult, error) {
	if err := validateWriterConfig(w.path, w.lockTimeout); err != nil {
		return CommitResult{}, err
	}
	if err := ensureSecureParent(w.path); err != nil {
		return CommitResult{}, err
	}

	var result CommitResult
	err := withFileLock(ctx, w.path+".lock", w.lockTimeout, func() error {
		current, _, err := readSnapshot(w.path)
		if err == nil {
			result = commitResult(current, false)
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}

		initial := snapshot{
			Version:    snapshotVersion,
			Generation: 1,
			UpdatedAt:  now.UTC().Unix(),
			Entries:    []entry{},
		}
		if err := writeSnapshotAtomic(w.path, initial); err != nil {
			return err
		}
		result = commitResult(initial, true)
		return nil
	})
	return result, err
}

// Revoke durably revokes every token with the given issuer and key ID.
// Retention is derived from the configured maximum token lifetime plus clock
// skew; repeated revocation never shortens an existing tombstone.
func (w *Writer) Revoke(ctx context.Context, issuer, keyID string, now time.Time, maxTokenTTL time.Duration) (CommitResult, error) {
	if err := validateWriterConfig(w.path, w.lockTimeout); err != nil {
		return CommitResult{}, err
	}
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(keyID) == "" {
		return CommitResult{}, errors.New("revocation issuer and key id must not be empty")
	}
	if len(issuer) > maxIdentifierBytes || len(keyID) > maxIdentifierBytes {
		return CommitResult{}, fmt.Errorf("revocation issuer and key id must not exceed %d bytes", maxIdentifierBytes)
	}
	if maxTokenTTL <= 0 {
		return CommitResult{}, errors.New("revocation token lifetime must be positive")
	}
	if err := ensureSecureParent(w.path); err != nil {
		return CommitResult{}, err
	}

	var result CommitResult
	err := withFileLock(ctx, w.path+".lock", w.lockTimeout, func() error {
		current, _, err := readSnapshot(w.path)
		if err != nil {
			return fmt.Errorf("reading initialized revocation snapshot: %w", err)
		}

		now = now.UTC()
		desiredRetention := now.Add(maxTokenTTL + revocationClockSkew).Unix()
		kept := make([]entry, 0, len(current.Entries)+1)
		found := false
		changed := false
		for _, item := range current.Entries {
			if item.RetainUntil <= now.Unix() {
				changed = true
				continue
			}
			if item.Issuer == issuer && item.KeyID == keyID {
				found = true
			}
			kept = append(kept, item)
		}
		if !found {
			kept = append(kept, entry{
				Issuer:      issuer,
				KeyID:       keyID,
				RevokedAt:   now.Unix(),
				RetainUntil: desiredRetention,
			})
			changed = true
		}
		if !changed {
			result = commitResult(current, false)
			return nil
		}

		sort.Slice(kept, func(i, j int) bool {
			if kept[i].Issuer == kept[j].Issuer {
				return kept[i].KeyID < kept[j].KeyID
			}
			return kept[i].Issuer < kept[j].Issuer
		})
		next := snapshot{
			Version:    snapshotVersion,
			Generation: current.Generation + 1,
			UpdatedAt:  now.Unix(),
			Entries:    kept,
		}
		if err := writeSnapshotAtomic(w.path, next); err != nil {
			return err
		}
		result = commitResult(next, true)
		return nil
	})
	return result, err
}

func validateWriterConfig(path string, timeout time.Duration) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("revocation snapshot path must not be empty")
	}
	if timeout <= 0 {
		return errors.New("revocation writer lock timeout must be positive")
	}
	return nil
}

func commitResult(s snapshot, changed bool) CommitResult {
	return CommitResult{
		Generation: s.Generation,
		UpdatedAt:  time.Unix(s.UpdatedAt, 0).UTC(),
		Changed:    changed,
	}
}

type readerState struct {
	generation uint64
	digest     [sha256.Size]byte
	revoked    map[string]struct{}
	err        error
}

// Reader polls a durable snapshot and serves request-path checks from an
// immutable in-memory view.
type Reader struct {
	path     string
	interval time.Duration
	state    atomic.Pointer[readerState]
	stop     chan struct{}
	done     chan struct{}
	close    sync.Once
}

// NewReader validates initial state and starts a background refresh loop.
func NewReader(path string, interval time.Duration) (*Reader, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("revocation snapshot path must not be empty")
	}
	if interval <= 0 {
		return nil, errors.New("revocation refresh interval must be positive")
	}
	r := &Reader{
		path:     path,
		interval: interval,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	if err := r.Refresh(); err != nil {
		return nil, err
	}
	go r.poll()
	return r, nil
}

// Refresh strictly loads and publishes one complete snapshot. On any error it
// publishes an unavailable state so Auth fails closed until a valid non-
// rollback generation is observed.
func (r *Reader) Refresh() error {
	s, digest, err := readSnapshot(r.path)
	current := r.state.Load()
	if err == nil && current != nil {
		switch {
		case s.Generation < current.generation:
			err = ErrRollback
		case s.Generation == current.generation && digest != current.digest:
			err = fmt.Errorf("%w: generation content changed", ErrRollback)
		}
	}
	if err != nil {
		generation := uint64(0)
		var previousDigest [sha256.Size]byte
		if current != nil {
			generation = current.generation
			previousDigest = current.digest
		}
		r.state.Store(&readerState{
			generation: generation,
			digest:     previousDigest,
			revoked:    map[string]struct{}{},
			err:        fmt.Errorf("%w: %v", ErrUnavailable, err),
		})
		return err
	}

	now := time.Now().Unix()
	revoked := make(map[string]struct{}, len(s.Entries))
	for _, item := range s.Entries {
		if item.RetainUntil > now {
			revoked[revocationKey(item.Issuer, item.KeyID)] = struct{}{}
		}
	}
	r.state.Store(&readerState{
		generation: s.Generation,
		digest:     digest,
		revoked:    revoked,
	})
	return nil
}

// Check reports whether a key ID is revoked. An error means no allow decision
// can be made safely.
func (r *Reader) Check(ctx context.Context, issuer, keyID string) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}
	state := r.state.Load()
	if state == nil || state.err != nil {
		if state != nil && state.err != nil {
			return false, state.err
		}
		return false, ErrUnavailable
	}
	_, ok := state.revoked[revocationKey(issuer, keyID)]
	return ok, nil
}

func (r *Reader) poll() {
	defer close(r.done)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = r.Refresh()
		case <-r.stop:
			return
		}
	}
}

// Close stops the refresh loop.
func (r *Reader) Close() error {
	r.close.Do(func() { close(r.stop) })
	<-r.done
	return nil
}

func revocationKey(issuer, keyID string) string {
	return issuer + "\x00" + keyID
}

func readSnapshot(path string) (snapshot, [sha256.Size]byte, error) {
	var zeroDigest [sha256.Size]byte
	if err := validateSecureParent(path); err != nil {
		return snapshot{}, zeroDigest, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return snapshot{}, zeroDigest, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return snapshot{}, zeroDigest, errors.New("revocation snapshot must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return snapshot{}, zeroDigest, fmt.Errorf("revocation snapshot permissions %o are not owner-only", info.Mode().Perm())
	}
	file, err := os.Open(path) // #nosec G304 -- path is explicit operator configuration and is lstat-validated above.
	if err != nil {
		return snapshot{}, zeroDigest, err
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, maxSnapshotBytes+1))
	if err != nil {
		return snapshot{}, zeroDigest, err
	}
	if len(raw) > maxSnapshotBytes {
		return snapshot{}, zeroDigest, errors.New("revocation snapshot exceeds size limit")
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var s snapshot
	if err := decoder.Decode(&s); err != nil {
		return snapshot{}, zeroDigest, fmt.Errorf("decoding revocation snapshot: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return snapshot{}, zeroDigest, errors.New("revocation snapshot contains multiple JSON values")
		}
		return snapshot{}, zeroDigest, fmt.Errorf("decoding trailing revocation data: %w", err)
	}
	if err := validateSnapshot(s); err != nil {
		return snapshot{}, zeroDigest, err
	}
	return s, sha256.Sum256(raw), nil
}

func validateSnapshot(s snapshot) error {
	if s.Version != snapshotVersion {
		return fmt.Errorf("unsupported revocation snapshot version %d", s.Version)
	}
	if s.Generation == 0 || s.UpdatedAt <= 0 {
		return errors.New("revocation snapshot generation and updated_at must be positive")
	}
	if len(s.Entries) > maxSnapshotEntries {
		return errors.New("revocation snapshot entry limit exceeded")
	}
	seen := make(map[string]struct{}, len(s.Entries))
	for _, item := range s.Entries {
		if strings.TrimSpace(item.Issuer) == "" || strings.TrimSpace(item.KeyID) == "" {
			return errors.New("revocation entry issuer and kid must not be empty")
		}
		if len(item.Issuer) > maxIdentifierBytes || len(item.KeyID) > maxIdentifierBytes {
			return fmt.Errorf("revocation entry issuer and kid must not exceed %d bytes", maxIdentifierBytes)
		}
		if item.RevokedAt <= 0 || item.RetainUntil <= item.RevokedAt {
			return errors.New("revocation entry timestamps are invalid")
		}
		key := revocationKey(item.Issuer, item.KeyID)
		if _, exists := seen[key]; exists {
			return errors.New("revocation snapshot contains duplicate issuer/kid")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func ensureSecureParent(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating revocation directory: %w", err)
	}
	return validateSecureParent(path)
}

func validateSecureParent(path string) error {
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("revocation parent must be a non-symlink directory")
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("revocation directory permissions %o allow group/other writes", info.Mode().Perm())
	}
	return nil
}

func writeSnapshotAtomic(path string, s snapshot) error {
	if err := ensureSecureParent(path); err != nil {
		return err
	}
	if err := validateSnapshot(s); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding revocation snapshot: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > maxSnapshotBytes {
		return errors.New("revocation snapshot exceeds size limit")
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".revocation-*.tmp")
	if err != nil {
		return fmt.Errorf("creating revocation temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing revocation snapshot: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("syncing revocation snapshot: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing revocation snapshot: %w", err)
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to replace symlink revocation snapshot")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("committing revocation snapshot: %w", err)
	}
	dirHandle, err := os.Open(dir) // #nosec G304 -- dir is the validated configured state directory.
	if err != nil {
		return fmt.Errorf("opening revocation directory for sync: %w", err)
	}
	defer func() { _ = dirHandle.Close() }()
	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("syncing revocation directory: %w", err)
	}
	return nil
}
