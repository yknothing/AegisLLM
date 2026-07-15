package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yknothing/AegisLLM/internal/config"
	"github.com/yknothing/AegisLLM/internal/kms/factory"
	"github.com/yknothing/AegisLLM/internal/virtualkey"
)

func TestOperatorProviderKeyImportUsesBoundedNonTTYStdin(t *testing.T) {
	configPath := writeOperatorTestConfig(t)
	var stdout, stderr bytes.Buffer
	secret := "sk-cli-provider-secret"

	exitCode := runOperator(
		[]string{"provider-key", "import", "--config", configPath, "--provider", "openai-primary"},
		strings.NewReader(secret+"\n"), true, &stdout, &stderr,
	)
	if exitCode == 0 || !strings.Contains(stderr.String(), "terminal") {
		t.Fatalf("TTY import exit=%d stderr=%q, want rejection", exitCode, stderr.String())
	}
	if strings.Contains(stderr.String(), secret) {
		t.Fatal("TTY rejection leaked provider key")
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = runOperator(
		[]string{"provider-key", "import", "--config", configPath, "--provider", "openai-primary"},
		strings.NewReader(secret+"\n"), false, &stdout, &stderr,
	)
	if exitCode != 0 {
		t.Fatalf("import exit=%d stderr=%q", exitCode, stderr.String())
	}
	if stdout.Len() != 0 || strings.Contains(stderr.String(), secret) {
		t.Fatalf("import output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	cfg, err := config.LoadForOperator(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	store, err := factory.NewOperatorStore(cfg.KMS)
	if err != nil {
		t.Fatalf("open KMS: %v", err)
	}
	defer func() { _ = store.Close() }()
	key, err := store.GetKey(context.Background(), "openai-key-1")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	defer key.Close()
	if string(key.Bytes()) != secret {
		t.Fatalf("stored key = %q, want stdin value without newline", key.Bytes())
	}
}

func TestOperatorVirtualKeyIssueRequiresExplicitSecretOutput(t *testing.T) {
	configPath := writeOperatorTestConfig(t)
	args := []string{
		"virtual-key", "issue", "--config", configPath,
		"--subject", "client-1", "--models", "gpt-4o-mini", "--ttl", "1h",
	}
	var stdout, stderr bytes.Buffer
	if code := runOperator(args, strings.NewReader(""), false, &stdout, &stderr); code == 0 {
		t.Fatal("virtual-key issue succeeded without --out or --stdout")
	}

	stdout.Reset()
	stderr.Reset()
	if code := runOperator(append(args, "--stdout"), strings.NewReader(""), false, &stdout, &stderr); code != 0 {
		t.Fatalf("virtual-key issue --stdout failed: %s", stderr.String())
	}
	token := strings.TrimSpace(stdout.String())
	if strings.Contains(token, " ") || strings.Count(token, ".") != 2 {
		t.Fatalf("stdout = %q, want token only", stdout.String())
	}
	validated, err := virtualkey.Validate(token, []byte("0123456789abcdef0123456789abcdef"), "aegis", 24*time.Hour)
	if err != nil {
		t.Fatalf("Validate issued token: %v", err)
	}
	if validated.Subject != "client-1" {
		t.Fatalf("subject = %q, want client-1", validated.Subject)
	}
}

func TestOperatorVirtualKeyIssueCreatesExclusiveOwnerOnlyOutput(t *testing.T) {
	configPath := writeOperatorTestConfig(t)
	outPath := filepath.Join(t.TempDir(), "virtual-key.jwt")
	args := []string{
		"virtual-key", "issue", "--config", configPath,
		"--subject", "client-1", "--models", "gpt-4o-mini", "--ttl", "1h",
		"--out", outPath,
	}
	var stdout, stderr bytes.Buffer
	if code := runOperator(args, strings.NewReader(""), false, &stdout, &stderr); code != 0 {
		t.Fatalf("issue --out failed: %s", stderr.String())
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("Stat output: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("output mode = %v, want 0600", info.Mode().Perm())
	}
	before, _ := os.ReadFile(outPath)
	if code := runOperator(args, strings.NewReader(""), false, &stdout, &stderr); code == 0 {
		t.Fatal("issue overwrote existing output file")
	}
	after, _ := os.ReadFile(outPath)
	if !bytes.Equal(before, after) {
		t.Fatal("existing token output changed after exclusive-create failure")
	}
}

func TestOperatorRevocationInitAndRevoke(t *testing.T) {
	configPath := writeOperatorTestConfig(t)
	var stdout, stderr bytes.Buffer
	if code := runOperator([]string{"revocation", "init", "--config", configPath}, strings.NewReader(""), false, &stdout, &stderr); code != 0 {
		t.Fatalf("revocation init failed: %s", stderr.String())
	}
	stderr.Reset()
	if code := runOperator([]string{"virtual-key", "revoke", "--config", configPath, "--kid", "vk_test"}, strings.NewReader(""), false, &stdout, &stderr); code != 0 {
		t.Fatalf("virtual-key revoke failed: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "generation=") || !strings.Contains(stderr.String(), "visible_by=") {
		t.Fatalf("revoke status = %q, want durable generation and visibility bound", stderr.String())
	}
}

func TestOperatorRejectsOversizedProviderKeyWithoutLeakingInput(t *testing.T) {
	configPath := writeOperatorTestConfig(t)
	secret := strings.Repeat("s", maxProviderKeyBytes+1)
	var stdout, stderr bytes.Buffer
	code := runOperator(
		[]string{"provider-key", "import", "--config", configPath, "--provider", "openai-primary"},
		strings.NewReader(secret), false, &stdout, &stderr,
	)
	if code == 0 || !strings.Contains(stderr.String(), "size limit") {
		t.Fatalf("oversized import exit=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stderr.String(), secret) {
		t.Fatal("oversized import leaked secret")
	}
}

func TestOperatorRejectsUnexpectedPositionalArgumentsWithoutReflection(t *testing.T) {
	configPath := writeOperatorTestConfig(t)
	unexpected := "sk-must-not-be-reflected"
	var stdout, stderr bytes.Buffer
	code := runOperator(
		[]string{"revocation", "init", "--config", configPath, unexpected},
		strings.NewReader(""), false, &stdout, &stderr,
	)
	if code == 0 || !strings.Contains(stderr.String(), "positional") {
		t.Fatalf("unexpected argument exit=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stderr.String(), unexpected) {
		t.Fatal("unexpected positional argument was reflected")
	}
}

func TestOperatorHelpReturnsSuccess(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"revocation", "init", "--help"}} {
		var stdout, stderr bytes.Buffer
		if code := runOperator(args, strings.NewReader(""), false, &stdout, &stderr); code != 0 {
			t.Fatalf("runOperator(%v) exit=%d stdout=%q stderr=%q, want success", args, code, stdout.String(), stderr.String())
		}
		if strings.Contains(stderr.String(), "operator error:") {
			t.Fatalf("runOperator(%v) rendered help as an error: %q", args, stderr.String())
		}
	}
}

func TestOperatorProviderKeyReadFailureDoesNotLeakPartialInput(t *testing.T) {
	configPath := writeOperatorTestConfig(t)
	secret := "sk-partial-secret"
	var stdout, stderr bytes.Buffer
	code := runOperator(
		[]string{"provider-key", "import", "--config", configPath, "--provider", "openai-primary"},
		&failingReader{value: []byte(secret)}, false, &stdout, &stderr,
	)
	if code == 0 || !strings.Contains(stderr.String(), "reading provider key") {
		t.Fatalf("read failure exit=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
		t.Fatal("provider-key read failure leaked partial input")
	}
}

func TestOperatorKMSMigrateDryRunAndApply(t *testing.T) {
	configPath := writeOperatorTestConfig(t)
	var stdout, stderr bytes.Buffer
	if code := runOperator(
		[]string{"kms", "migrate", "--config", configPath, "--dry-run"},
		strings.NewReader(""), false, &stdout, &stderr,
	); code != 0 {
		t.Fatalf("KMS dry-run exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "kms_migration total=0 legacy=0 v2=0 migrated=0 dry_run=true") {
		t.Fatalf("KMS dry-run status=%q", stderr.String())
	}

	stderr.Reset()
	backupDir := filepath.Join(t.TempDir(), "migration-backup")
	if code := runOperator(
		[]string{"kms", "migrate", "--config", configPath, "--apply", "--backup-dir", backupDir},
		strings.NewReader(""), false, &stdout, &stderr,
	); code != 0 {
		t.Fatalf("KMS apply exit=%d stderr=%q", code, stderr.String())
	}
	if info, err := os.Stat(backupDir); err != nil || !info.IsDir() {
		t.Fatalf("KMS backup directory info=%v err=%v", info, err)
	}
}

type failingReader struct {
	value []byte
	done  bool
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, fmt.Errorf("injected read failure")
	}
	r.done = true
	return copy(p, r.value), fmt.Errorf("injected read failure")
}

func writeOperatorTestConfig(t *testing.T) string {
	t.Helper()
	const masterEnv = "TEST_CLI_MASTER"
	const jwtEnv = "TEST_CLI_JWT"
	t.Setenv(masterEnv, hex.EncodeToString(make([]byte, 32)))
	t.Setenv(jwtEnv, "0123456789abcdef0123456789abcdef")
	root := t.TempDir()
	path := filepath.Join(root, "aegis.json")
	data := fmt.Sprintf(`{
  "kms": {"mode":"local","local":{"master_key_env":%q,"key_store_path":%q}},
  "providers": [{"id":"openai-primary","name":"OpenAI","type":"openai","base_url":"https://api.openai.com","api_key_id":"openai-key-1","models":["gpt-4o-mini"],"enabled":true}],
  "auth": {"jwt_signing_key_env":%q,"token_expiry":"24h","issuer":"aegis","revocation":{"backend":"file","file_path":%q,"refresh_interval":"500ms"}},
  "quota": {"enabled":false},
  "egress": {"allowed_domains":["api.openai.com"]}
}`, masterEnv, filepath.Join(root, "keys"), jwtEnv, filepath.Join(root, "revocation", "state.json"))
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
