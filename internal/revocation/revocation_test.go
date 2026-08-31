package revocation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/yknothing/AegisLLM/internal/virtualkey"
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

func TestWriterRepeatedRevocationExtendsTombstone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	writer := NewWriter(path, 2*time.Second)
	now := time.Unix(1_800_000_000, 0).UTC()
	if _, err := writer.Init(context.Background(), now); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}

	first, err := writer.Revoke(context.Background(), "aegis", "vk_one", now, time.Hour)
	if err != nil {
		t.Fatalf("first Revoke returned error: %v", err)
	}
	extendedAt := now.Add(30 * time.Minute)
	second, err := writer.Revoke(context.Background(), "aegis", "vk_one", extendedAt, time.Hour)
	if err != nil {
		t.Fatalf("second Revoke returned error: %v", err)
	}
	if !second.Changed || second.Generation != first.Generation+1 {
		t.Fatalf("second result = %+v, want changed generation %d", second, first.Generation+1)
	}

	state, _, err := readSnapshot(path)
	if err != nil {
		t.Fatalf("readSnapshot returned error: %v", err)
	}
	if len(state.Entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(state.Entries))
	}
	wantRetention := extendedAt.Add(time.Hour + revocationClockSkew).Unix()
	if state.Entries[0].RetainUntil != wantRetention {
		t.Fatalf("retain_until = %d, want %d", state.Entries[0].RetainUntil, wantRetention)
	}

	idempotent, err := writer.Revoke(context.Background(), "aegis", "vk_one", extendedAt, time.Hour)
	if err != nil {
		t.Fatalf("idempotent Revoke returned error: %v", err)
	}
	if idempotent.Changed || idempotent.Generation != second.Generation {
		t.Fatalf("idempotent result = %+v, want unchanged generation %d", idempotent, second.Generation)
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

func TestReadSnapshotRejectsAmbiguousOrNonCanonicalJSONMembers(t *testing.T) {
	const (
		canary    = "CANARY_REVOCATION_MEMBER_VALUE_4f27"
		canonical = `{"version":1,"generation":7,"updated_at":1800000000,"entries":[{"issuer":"` + canary + `","kid":"vk_one","revoked_at":1800000000,"retain_until":1800003600}]}`
	)

	tests := []struct {
		name string
		old  string
		new  string
	}{
		{
			name: "root generation duplicate",
			old:  `"generation":7`,
			new:  `"generation":8,"generation":7`,
		},
		{
			name: "root generation ASCII case-fold collision",
			old:  `"generation":7`,
			new:  `"GENERATION":8,"generation":7`,
		},
		{
			name: "root generation sole case mismatch",
			old:  `"generation":7`,
			new:  `"GENERATION":7`,
		},
		{
			name: "root entries duplicate",
			old:  `"entries":[`,
			new:  `"entries":[],"entries":[`,
		},
		{
			name: "root entries ASCII case-fold collision",
			old:  `"entries":[`,
			new:  `"ENTRIES":[],"entries":[`,
		},
		{
			name: "root entries sole case mismatch",
			old:  `"entries":[`,
			new:  `"ENTRIES":[`,
		},
		{
			name: "entry retain_until duplicate",
			old:  `"retain_until":1800003600`,
			new:  `"retain_until":1800007200,"retain_until":1800003600`,
		},
		{
			name: "entry retain_until ASCII case-fold collision",
			old:  `"retain_until":1800003600`,
			new:  `"RETAIN_UNTIL":1800007200,"retain_until":1800003600`,
		},
		{
			name: "entry retain_until sole case mismatch",
			old:  `"retain_until":1800003600`,
			new:  `"RETAIN_UNTIL":1800003600`,
		},
		{
			name: "entry kid duplicate",
			old:  `"kid":"vk_one"`,
			new:  `"kid":"` + canary + `","kid":"vk_one"`,
		},
		{
			name: "entry kid ASCII case-fold collision",
			old:  `"kid":"vk_one"`,
			new:  `"KID":"` + canary + `","kid":"vk_one"`,
		},
		{
			name: "entry kid sole case mismatch",
			old:  `"kid":"vk_one"`,
			new:  `"KID":"vk_one"`,
		},
		{
			name: "entry issuer duplicate",
			old:  `"issuer":"` + canary + `"`,
			new:  `"issuer":"shadow","issuer":"` + canary + `"`,
		},
		{
			name: "entry issuer ASCII case-fold collision",
			old:  `"issuer":"` + canary + `"`,
			new:  `"ISSUER":"shadow","issuer":"` + canary + `"`,
		},
		{
			name: "entry issuer sole case mismatch",
			old:  `"issuer":"` + canary + `"`,
			new:  `"ISSUER":"` + canary + `"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := strings.Replace(canonical, tt.old, tt.new, 1)
			if raw == canonical {
				t.Fatal("fixture mutation did not match canonical snapshot")
			}

			_, _, err := readSnapshot(writeRawSnapshot(t, []byte(raw)))
			if err == nil {
				t.Fatal("readSnapshot accepted ambiguous or non-canonical JSON member")
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatalf("readSnapshot error leaked snapshot value: %v", err)
			}
		})
	}
}

func TestReadSnapshotRejectsInvalidUnicodeJSONStrings(t *testing.T) {
	const (
		canary    = "CANARY_REVOCATION_UNICODE_VALUE_82c1"
		canonical = `{"version":1,"generation":7,"updated_at":1800000000,"entries":[{"issuer":"` + canary + `","kid":"vk_one","revoked_at":1800000000,"retain_until":1800003600}]}`
	)

	tests := []struct {
		name string
		raw  []byte
	}{
		{
			name: "raw invalid UTF-8 member name",
			raw: []byte(strings.Replace(
				canonical,
				`"issuer"`,
				`"`+canary+"\xff"+`"`,
				1,
			)),
		},
		{
			name: "lone surrogate member name",
			raw: []byte(strings.Replace(
				canonical,
				`"issuer"`,
				`"`+canary+`\ud800"`,
				1,
			)),
		},
		{
			name: "raw invalid UTF-8 string value",
			raw:  []byte(strings.Replace(canonical, canary, canary+"\xff", 1)),
		},
		{
			name: "lone surrogate string value",
			raw:  []byte(strings.Replace(canonical, canary, canary+`\ud800`, 1)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := readSnapshot(writeRawSnapshot(t, tt.raw))
			if err == nil {
				t.Fatal("readSnapshot accepted JSON with invalid Unicode")
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatalf("readSnapshot error leaked snapshot value: %v", err)
			}
		})
	}
}

func writeRawSnapshot(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write raw snapshot: %v", err)
	}
	return path
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

func TestReaderRejectsHigherGenerationThatDropsLiveTombstone(t *testing.T) {
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

	current, _, err := readSnapshot(path)
	if err != nil {
		t.Fatalf("readSnapshot returned error: %v", err)
	}
	forged := snapshot{
		Version:    snapshotVersion,
		Generation: current.Generation + 1,
		UpdatedAt:  now.Add(time.Second).Unix(),
		Entries:    []entry{},
	}
	if err := writeSnapshotAtomic(path, forged); err != nil {
		t.Fatalf("write higher-generation snapshot: %v", err)
	}
	if err := reader.Refresh(); !errors.Is(err, ErrRollback) {
		t.Fatalf("Refresh tombstone-removal error = %v, want ErrRollback", err)
	}
	if _, err := reader.Check(context.Background(), "aegis", "vk_one"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Check after tombstone removal error = %v, want ErrUnavailable", err)
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

func TestSnapshotOpenRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		file, openErr := openSnapshotNoFollow(path)
		if file != nil {
			_ = file.Close()
		}
		result <- openErr
	}()
	select {
	case <-result:
	case <-time.After(100 * time.Millisecond):
		writer, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatalf("unblock FIFO reader: %v", err)
		}
		_ = writer.Close()
		<-result
		t.Fatal("revocation snapshot open blocked on a FIFO")
	}

	if _, _, err := readSnapshot(path); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("readSnapshot FIFO error = %v, want regular-file rejection", err)
	}
}

func TestWriterRejectsTokenLifetimeThatWouldOverflowRetention(t *testing.T) {
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

	_, err = writer.Revoke(context.Background(), "aegis", "vk_one", now, virtualkey.MaxTokenTTL+time.Nanosecond)
	if err == nil || !strings.Contains(err.Error(), "maximum supported") {
		t.Fatalf("Revoke unsafe token lifetime error = %v, want supported-maximum rejection", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("snapshot changed after unsafe token lifetime rejection")
	}
}
