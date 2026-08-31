//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSIGTERMDuringActiveGatewayLeavesNoPASSProcessGroupMarkerOrTemporaryRoot(t *testing.T) {
	repositoryRoot := rollbackRepositoryRoot(t)
	testRoot := t.TempDir()
	fixture := buildProductionSignalFixture(t, repositoryRoot, testRoot)
	drillTempParent := filepath.Join(testRoot, "drill-tmp")
	if err := os.Mkdir(drillTempParent, 0o700); err != nil {
		t.Fatal(err)
	}
	inputLock := filepath.Join(testRoot, "rollback-input-lock.json")
	lockBytes := signalInputLockJSON(t, fixture)
	if err := os.WriteFile(inputLock, lockBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	lockDigest := fmt.Sprintf("%x", sha256.Sum256(lockBytes))

	command := exec.Command(fixture.runner,
		"--candidate-bin", fixture.candidate,
		"--rollback-bin", fixture.rollback,
		"--input-lock", inputLock,
		"--input-lock-sha256", lockDigest,
		"--repo-root", repositoryRoot,
		"--allow-dirty-iteration",
	)
	command.Env = append(identityEnvironment(), "TMPDIR="+drillTempParent)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()

	drillRoot, pgid := waitForProductionGateway(t, drillTempParent, wait, &stdout, &stderr, 10*time.Second)
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM to production rollback runner: %v", err)
	}
	var waitErr error
	select {
	case waitErr = <-wait:
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		t.Fatal("production rollback runner did not exit after SIGTERM")
	}

	// Always reap a vulnerable implementation's escaped gateway before making
	// assertions so this RED test cannot leak a process into the ceo test host.
	deferredMarker := filepath.Join(drillTempParent, "production-gateway-marker")
	time.Sleep(1100 * time.Millisecond)
	markerErr := statAbsent(deferredMarker)
	rootErr := statAbsent(drillRoot)
	groupErr := waitForProcessGroupAbsence(pgid, 100*time.Millisecond)
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	_ = os.RemoveAll(drillRoot)

	if exitError, ok := waitErr.(*exec.ExitError); ok {
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			t.Errorf("production rollback runner retained default signal termination: %s", status.Signal())
		}
	} else if waitErr == nil {
		t.Error("interrupted production rollback runner exited successfully")
	} else {
		t.Errorf("production rollback runner wait error = %v", waitErr)
	}
	if strings.Contains(stdout.String(), `"result":"PASS"`) || strings.Contains(stderr.String(), `"result":"PASS"`) {
		t.Errorf("interrupted rollback emitted PASS evidence: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if rootErr != nil {
		t.Errorf("interrupted rollback temporary root was not removed: %v", rootErr)
	}
	if markerErr != nil {
		t.Errorf("interrupted gateway reached delayed marker: %v", markerErr)
	}
	if groupErr != nil {
		t.Errorf("gateway process group survived runner SIGTERM: %v", groupErr)
	}
}

type productionSignalFixture struct {
	runner          string
	candidate       string
	rollback        string
	candidateSHA    string
	candidateDigest string
	rollbackDigest  string
	runnerDigest    string
}

func buildProductionSignalFixture(t *testing.T, repositoryRoot, testRoot string) productionSignalFixture {
	t.Helper()
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("locate Go for production signal fixture: %v", err)
	}
	gitBinary, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("locate Git for production signal fixture: %v", err)
	}
	goModCacheCommand := exec.Command(goBinary, "env", "GOMODCACHE")
	goModCacheBytes, err := goModCacheCommand.Output()
	if err != nil {
		t.Fatalf("resolve existing Go module cache: %v", err)
	}
	goModCache := strings.TrimSpace(string(goModCacheBytes))
	if !filepath.IsAbs(goModCache) {
		t.Fatalf("Go module cache is not absolute: %q", goModCache)
	}
	environment := signalBuildEnvironment(testRoot, goModCache)
	candidateSHA := signalCommandOutput(t, gitBinary, repositoryRoot, environment, "rev-parse", "--verify", "HEAD")
	if !fullSHA.MatchString(candidateSHA) {
		t.Fatalf("candidate SHA fixture = %q", candidateSHA)
	}
	repositoryDirty := signalCommandOutput(t, gitBinary, repositoryRoot, environment,
		"status", "--porcelain=v1", "--untracked-files=all") != ""

	runner := filepath.Join(testRoot, "aegis-rollback-drill")
	signalRunCommand(t, goBinary, repositoryRoot, environment,
		"build", "-trimpath", "-o", runner, "./cmd/aegis-rollback-drill")
	assertSignalBuildInfo(t, runner, aegisModulePath+"/cmd/aegis-rollback-drill", candidateSHA, repositoryDirty)

	fixtureRepo := filepath.Join(testRoot, "fixture-repo")
	if err := os.MkdirAll(filepath.Join(fixtureRepo, "cmd", "aegis"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureRepo, "go.mod"), []byte("module "+aegisModulePath+"\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureRepo, "cmd", "aegis", "main.go"), []byte(signalGatewayFixtureSource), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "rollback-signal@example.invalid"},
		{"config", "user.name", "Rollback Signal Fixture"},
		{"add", "go.mod", "cmd/aegis/main.go"},
		{"commit", "-qm", "fixture"},
	} {
		signalRunCommand(t, gitBinary, fixtureRepo, environment, arguments...)
	}
	fixtureRevision := signalCommandOutput(t, gitBinary, fixtureRepo, environment, "rev-parse", "--verify", "HEAD")

	rollback := filepath.Join(testRoot, "aegis-v0.2.0")
	signalRunCommand(t, goBinary, fixtureRepo, environment,
		"build", "-trimpath", "-o", rollback,
		"-ldflags=-X main.version=v0.2.0 -X main.commit="+rollbackV020SHA,
		"./cmd/aegis")
	replaceSignalBuildRevision(t, rollback, fixtureRevision, rollbackV020SHA)
	assertSignalBuildInfo(t, rollback, aegisMainPackagePath, rollbackV020SHA, false)

	if repositoryDirty {
		if err := os.WriteFile(filepath.Join(fixtureRepo, "dirty-marker"), []byte("candidate iteration\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	candidate := filepath.Join(testRoot, "aegis-v0.2.1")
	signalRunCommand(t, goBinary, fixtureRepo, environment,
		"build", "-trimpath", "-o", candidate,
		"-ldflags=-X main.version=v0.2.1 -X main.commit="+candidateSHA,
		"./cmd/aegis")
	replaceSignalBuildRevision(t, candidate, fixtureRevision, candidateSHA)
	assertSignalBuildInfo(t, candidate, aegisMainPackagePath, candidateSHA, repositoryDirty)

	return productionSignalFixture{
		runner:          runner,
		candidate:       candidate,
		rollback:        rollback,
		candidateSHA:    candidateSHA,
		candidateDigest: signalFileDigest(t, candidate),
		rollbackDigest:  signalFileDigest(t, rollback),
		runnerDigest:    signalFileDigest(t, runner),
	}
}

func signalInputLockJSON(t *testing.T, fixture productionSignalFixture) []byte {
	t.Helper()
	v2 := []byte(fmt.Sprintf(`{
  "schema": "aegis.rollback-input-lock/v2",
  "run_id": %q,
  "containment_nonce": %q,
  "candidate_sha": %q,
  "candidate_binary_sha256": %q,
  "candidate_provenance_ref": "https://evidence.example/candidate.intoto.jsonl",
  "candidate_provenance_sha256": %q,
  "rollback_tag": "v0.2.0",
  "rollback_sha": %q,
  "rollback_binary_sha256": %q,
  "rollback_provenance_ref": "https://evidence.example/v0.2.0.intoto.jsonl",
  "rollback_provenance_sha256": %q,
  "runner_binary_sha256": %q,
  "runner_provenance_ref": "https://evidence.example/rollback-runner.intoto.jsonl",
  "runner_provenance_sha256": %q,
  "trust_policy_uri": "https://trust.example/policy/v1.json",
  "trust_policy_sha256": %q,
  "builder_identity": "https://builder.example/workflows/release@v1",
  "created_at": "2026-08-20T00:00:00Z"
}
`, testRollbackRunID, testRollbackContainmentNonce, fixture.candidateSHA, fixture.candidateDigest,
		strings.Repeat("a", 64), rollbackV020SHA, fixture.rollbackDigest, strings.Repeat("b", 64),
		fixture.runnerDigest, strings.Repeat("d", 64), strings.Repeat("c", 64)))
	if _, err := parseRollbackInputLock(v2); err == nil {
		return v2
	}

	// The legacy fixture exists only so this regression test demonstrably fails
	// against the pre-fix v1 runner. Current production code always selects v2.
	v1 := []byte(fmt.Sprintf(`{
  "schema": "aegis.rollback-input-lock/v1",
  "candidate_sha": %q,
  "candidate_binary_sha256": %q,
  "candidate_provenance_ref": "https://evidence.example/candidate.intoto.jsonl",
  "candidate_provenance_sha256": %q,
  "rollback_tag": "v0.2.0",
  "rollback_sha": %q,
  "rollback_binary_sha256": %q,
  "rollback_provenance_ref": "https://evidence.example/v0.2.0.intoto.jsonl",
  "rollback_provenance_sha256": %q,
  "trust_policy_uri": "https://trust.example/policy/v1.json",
  "trust_policy_sha256": %q,
  "builder_identity": "https://builder.example/workflows/release@v1",
  "created_at": "2026-08-20T00:00:00Z"
}
`, fixture.candidateSHA, fixture.candidateDigest, strings.Repeat("a", 64), rollbackV020SHA,
		fixture.rollbackDigest, strings.Repeat("b", 64), strings.Repeat("c", 64)))
	if _, err := parseRollbackInputLock(v1); err != nil {
		t.Fatalf("neither v2 nor exact legacy v1 signal fixture lock matches the parser: %v", err)
	}
	return v1
}

func signalBuildEnvironment(testRoot, goModCache string) []string {
	return []string{
		"CGO_ENABLED=0",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GOCACHE=" + filepath.Join(testRoot, "go-cache"),
		"GOENV=off",
		"GOFLAGS=-mod=readonly",
		"GOMODCACHE=" + goModCache,
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"HOME=/nonexistent",
		"LANG=C",
		"PATH=/usr/bin:/bin",
		"TZ=UTC",
	}
}

func signalRunCommand(t *testing.T, executable, directory string, environment []string, arguments ...string) {
	t.Helper()
	command := exec.Command(executable, arguments...)
	command.Dir = directory
	command.Env = environment
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run %s %s: %v\n%s", executable, strings.Join(arguments, " "), err, output)
	}
}

func signalCommandOutput(t *testing.T, executable, directory string, environment []string, arguments ...string) string {
	t.Helper()
	command := exec.Command(executable, arguments...)
	command.Dir = directory
	command.Env = environment
	output, err := command.Output()
	if err != nil {
		t.Fatalf("run %s %s: %v", executable, strings.Join(arguments, " "), err)
	}
	return strings.TrimSpace(string(output))
}

func replaceSignalBuildRevision(t *testing.T, path, from, to string) {
	t.Helper()
	if len(from) != len(to) || !fullSHA.MatchString(from) || !fullSHA.MatchString(to) {
		t.Fatalf("invalid build revision replacement %q -> %q", from, to)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(from)) {
		t.Fatalf("fixture binary %s does not contain build revision %s", path, from)
	}
	data = bytes.ReplaceAll(data, []byte(from), []byte(to))
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
}

func assertSignalBuildInfo(t *testing.T, path, packagePath, revision string, modified bool) {
	t.Helper()
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture buildinfo %s: %v", path, err)
	}
	if info.Path != packagePath || info.Main.Path != aegisModulePath {
		t.Fatalf("fixture build identity path=%q module=%q", info.Path, info.Main.Path)
	}
	settings := make(map[string]string)
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	wantModified := strconv.FormatBool(modified)
	if settings["vcs.revision"] != revision || settings["vcs.modified"] != wantModified {
		t.Fatalf("fixture build identity revision=%q modified=%q, want %q/%q", settings["vcs.revision"], settings["vcs.modified"], revision, wantModified)
	}
}

func signalFileDigest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func waitForProductionGateway(t *testing.T, parent string, wait <-chan error, stdout, stderr *bytes.Buffer, timeout time.Duration) (string, int) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		roots, err := filepath.Glob(filepath.Join(parent, "aegis-rollback-drill-*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, root := range roots {
			ready := filepath.Join(root, "production-gateway-ready")
			pgidPath := filepath.Join(root, "production-gateway-pgid")
			if _, err := os.Stat(ready); err != nil {
				continue
			}
			pgidBytes, err := os.ReadFile(pgidPath)
			if err != nil {
				continue
			}
			pgid, err := strconv.Atoi(strings.TrimSpace(string(pgidBytes)))
			if err == nil && pgid > 0 {
				return root, pgid
			}
		}
		select {
		case err := <-wait:
			t.Fatalf("production rollback runner exited before startGateway: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("production rollback runner did not start the fixture gateway under %s", parent)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func statAbsent(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("%s still exists", path)
}

func waitForProcessGroupAbsence(pgid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Kill(-pgid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil && !errors.Is(err, syscall.EPERM) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("process group %d remains", pgid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

const signalGatewayFixtureSource = `package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var version = "dev"
var commit = "unknown"

type config struct {
	KMS struct {
		Local struct {
			Path string ` + "`json:\"key_store_path\"`" + `
		} ` + "`json:\"local\"`" + `
	} ` + "`json:\"kms\"`" + `
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("aegis %s (commit: %s, built: fixture)\n", version, commit)
		return
	}
	if len(os.Args) > 2 && os.Args[1] == "operator" {
		switch strings.Join(os.Args[1:3], " ") {
		case "operator kms":
			migration()
		case "operator revocation":
			return
		case "operator virtual-key":
			writeToken()
		default:
			os.Exit(2)
		}
		return
	}
	root := filepath.Dir(os.Getenv("TMPDIR"))
	_ = os.WriteFile(filepath.Join(root, "production-gateway-pgid"), []byte(fmt.Sprint(syscall.Getpgrp())), 0600)
	_ = os.WriteFile(filepath.Join(root, "production-gateway-ready"), []byte("ready"), 0600)
	marker := filepath.Join(filepath.Dir(root), "production-gateway-marker")
	go func() {
		time.Sleep(time.Second)
		_ = os.WriteFile(marker, []byte("marker"), 0600)
	}()
	for {
		time.Sleep(time.Hour)
	}
}

func migration() {
	configPath := flagValue("--config")
	data, err := os.ReadFile(configPath)
	if err != nil { os.Exit(3) }
	var parsed config
	if json.Unmarshal(data, &parsed) != nil { os.Exit(4) }
	entries, err := os.ReadDir(parsed.KMS.Local.Path)
	if err != nil || len(entries) != 1 { os.Exit(5) }
	keyPath := filepath.Join(parsed.KMS.Local.Path, entries[0].Name())
	key, err := os.ReadFile(keyPath)
	if err != nil { os.Exit(6) }
	legacy := !strings.HasPrefix(string(key), "fixture-v2:")
	if hasFlag("--apply") {
		backup := flagValue("--backup-dir")
		if os.Mkdir(backup, 0700) != nil { os.Exit(7) }
		output, err := os.OpenFile(filepath.Join(backup, entries[0].Name()), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil { os.Exit(8) }
		if _, err = output.Write(key); err != nil { os.Exit(9) }
		if output.Close() != nil { os.Exit(10) }
		if os.WriteFile(keyPath, append([]byte("fixture-v2:"), key...), 0600) != nil { os.Exit(11) }
		fmt.Fprintln(os.Stderr, "kms_migration total=1 legacy=1 v2=0 migrated=1 dry_run=false")
		return
	}
	if legacy {
		fmt.Fprintln(os.Stderr, "kms_migration total=1 legacy=1 v2=0 migrated=0 dry_run=true")
	} else {
		fmt.Fprintln(os.Stderr, "kms_migration total=1 legacy=0 v2=1 migrated=0 dry_run=true")
	}
}

func writeToken() {
	path := flagValue("--out")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil { os.Exit(12) }
	_, _ = io.WriteString(file, "fixture-token\n")
	if file.Close() != nil { os.Exit(13) }
}

func hasFlag(name string) bool {
	for _, argument := range os.Args { if argument == name { return true } }
	return false
}

func flagValue(name string) string {
	for index, argument := range os.Args[:len(os.Args)-1] {
		if argument == name { return os.Args[index+1] }
	}
	return ""
}
`
