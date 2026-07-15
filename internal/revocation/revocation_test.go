package revocation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWriterInitializesAndPersistsRevocationSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocation", "state.json")
	writer := NewWriter(path, 2*time.Second)
	now := time.Unix(1_800_000_000, 0).UTC()

	initResult, err := writer.Init(context.Background(), now)
	if err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	if initResult.Generation != 1 {
		t.Fatalf("initial generation = %d, want 1", initResult.Generation)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat returned error: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("snapshot mode = %v, want 0600", info.Mode().Perm())
	}

	result, err := writer.Revoke(context.Background(), "aegis", "vk_one", now, 24*time.Hour)
	if err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	if result.Generation != 2 {
		t.Fatalf("revoke generation = %d, want 2", result.Generation)
	}

	reader, err := NewReader(path, time.Hour)
	if err != nil {
		t.Fatalf("NewReader returned error: %v", err)
	}
	defer func() { _ = reader.Close() }()
	revoked, err := reader.Check(context.Background(), "aegis", "vk_one")
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if !revoked {
		t.Fatal("Check returned false for persisted revocation")
	}
}

func TestWriterConcurrentRevocationsProduceUnion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	writer := NewWriter(path, 5*time.Second)
	now := time.Now().UTC()
	if _, err := writer.Init(context.Background(), now); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}

	const count = 16
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, err := NewWriter(path, 5*time.Second).Revoke(
				context.Background(), "aegis", "vk_"+string(rune('a'+index)), now, time.Hour,
			)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Revoke returned error: %v", err)
		}
	}

	reader, err := NewReader(path, time.Hour)
	if err != nil {
		t.Fatalf("NewReader returned error: %v", err)
	}
	defer func() { _ = reader.Close() }()
	for i := 0; i < count; i++ {
		revoked, err := reader.Check(context.Background(), "aegis", "vk_"+string(rune('a'+i)))
		if err != nil || !revoked {
			t.Fatalf("Check(%d) = revoked=%v err=%v, want true nil", i, revoked, err)
		}
	}
}

func TestReaderFailsClosedOnCorruptionAndRecoversAtHigherGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	writer := NewWriter(path, 2*time.Second)
	now := time.Now().UTC()
	if _, err := writer.Init(context.Background(), now); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}

	reader, err := NewReader(path, time.Hour)
	if err != nil {
		t.Fatalf("NewReader returned error: %v", err)
	}
	defer func() { _ = reader.Close() }()

	if err := os.WriteFile(path, []byte(`{"version":`), 0600); err != nil {
		t.Fatalf("corrupt snapshot: %v", err)
	}
	if err := reader.Refresh(); err == nil {
		t.Fatal("Refresh accepted corrupted snapshot")
	}
	if _, err := reader.Check(context.Background(), "aegis", "vk_one"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Check corruption error = %v, want ErrUnavailable", err)
	}

	if _, err := writer.Init(context.Background(), now.Add(time.Second)); err == nil {
		t.Fatal("Init silently replaced corrupted existing snapshot")
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove corrupted snapshot: %v", err)
	}
	if _, err := writer.Init(context.Background(), now.Add(2*time.Second)); err != nil {
		t.Fatalf("reinitialize snapshot: %v", err)
	}
	if _, err := writer.Revoke(context.Background(), "aegis", "vk_one", now.Add(3*time.Second), time.Hour); err != nil {
		t.Fatalf("Revoke after reinitialize: %v", err)
	}
	if err := reader.Refresh(); err != nil {
		t.Fatalf("Refresh valid recovery returned error: %v", err)
	}
	revoked, err := reader.Check(context.Background(), "aegis", "vk_one")
	if err != nil || !revoked {
		t.Fatalf("Check after recovery = revoked=%v err=%v, want true nil", revoked, err)
	}
}

func TestReaderRejectsGenerationRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	writer := NewWriter(path, 2*time.Second)
	now := time.Now().UTC()
	if _, err := writer.Init(context.Background(), now); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	if _, err := writer.Revoke(context.Background(), "aegis", "vk_one", now, time.Hour); err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	reader, err := NewReader(path, time.Hour)
	if err != nil {
		t.Fatalf("NewReader returned error: %v", err)
	}
	defer func() { _ = reader.Close() }()

	rolledBack := snapshot{Version: snapshotVersion, Generation: 1, UpdatedAt: now.Unix(), Entries: []entry{}}
	if err := writeSnapshotAtomic(path, rolledBack); err != nil {
		t.Fatalf("write rollback snapshot: %v", err)
	}
	if err := reader.Refresh(); !errors.Is(err, ErrRollback) {
		t.Fatalf("Refresh rollback error = %v, want ErrRollback", err)
	}
	if _, err := reader.Check(context.Background(), "aegis", "vk_two"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Check rollback error = %v, want ErrUnavailable", err)
	}
}

func TestWriterRejectsOversizedIdentifierBeforeCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	writer := NewWriter(path, 2*time.Second)
	now := time.Now().UTC()
	if _, err := writer.Init(context.Background(), now); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile before: %v", err)
	}
	if _, err := writer.Revoke(context.Background(), "aegis", strings.Repeat("x", maxIdentifierBytes+1), now, time.Hour); err == nil {
		t.Fatal("Revoke accepted oversized key ID")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("snapshot changed after oversized identifier rejection")
	}
}
