package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/yknothing/AegisLLM/internal/utils"
)

const (
	drillProviderSecret = "ROLLBACK_DRILL_PROVIDER_SECRET_MUST_NOT_LEAK"
	drillJWTSigningKey  = "ROLLBACK_DRILL_JWT_KEY_MUST_NOT_LEAK"
)

func TestValidateOptionsRequiresLinuxHost(t *testing.T) {
	original := hostGOOS
	hostGOOS = "darwin"
	t.Cleanup(func() { hostGOOS = original })
	err := validateOptions(options{})
	var staged *stageError
	if !errors.As(err, &staged) || staged.Reason != "linux_host_required" {
		t.Fatalf("validateOptions error = %v, want linux_host_required", err)
	}
}

func TestValidateOptionsRejectsMissingOrMalformedExpectedDigests(t *testing.T) {
	original := hostGOOS
	hostGOOS = "linux"
	t.Cleanup(func() { hostGOOS = original })
	base := options{
		CandidateBinary: "/candidate", RollbackBinary: "/rollback",
		InputLock: "/input-lock.json", InputLockSHA256: strings.Repeat("b", 64), RepoRoot: "/repo",
	}
	missing := base
	missing.InputLock = ""
	err := validateOptions(missing)
	var staged *stageError
	if !errors.As(err, &staged) || staged.Reason != "required_flag_missing" {
		t.Fatalf("validateOptions missing lock error = %v, want required_flag_missing", err)
	}
	base.InputLockSHA256 = "deadbeef"
	err = validateOptions(base)
	staged = nil
	if !errors.As(err, &staged) || staged.Reason != "input_lock_sha256_not_full" {
		t.Fatalf("validateOptions error = %v, want input_lock_sha256_not_full", err)
	}
}

func TestLoadRollbackInputLockBindsExactBytesAndRequiredIdentities(t *testing.T) {
	data := validRollbackInputLockJSON()
	path := filepath.Join(t.TempDir(), "rollback-input-lock.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	expectedDigest := fmt.Sprintf("%x", sha256.Sum256(data))
	lock, digest, err := loadRollbackInputLock(path, expectedDigest)
	if err != nil {
		t.Fatalf("loadRollbackInputLock: %v", err)
	}
	if digest != expectedDigest || lock.Schema != rollbackInputLockSchema ||
		lock.CandidateSHA != strings.Repeat("a", 40) || lock.RollbackTag != "v0.2.0" ||
		lock.RollbackSHA != rollbackV020SHA {
		t.Fatalf("loaded lock identity mismatch: lock=%+v digest=%s", lock, digest)
	}
	if _, _, err := loadRollbackInputLock(path, strings.Repeat("0", 64)); err == nil {
		t.Fatal("loadRollbackInputLock accepted a mismatched expected digest")
	}
}

func TestRollbackInputLockRejectsUnknownDuplicateCaseFoldMissingAndTrailingData(t *testing.T) {
	valid := string(validRollbackInputLockJSON())
	variants := map[string]string{
		"unknown":   strings.Replace(valid, "\n}", ",\n  \"unexpected\": \"value\"\n}", 1),
		"duplicate": strings.Replace(valid, "\n}", ",\n  \"candidate_sha\": \""+strings.Repeat("a", 40)+"\"\n}", 1),
		"case-fold": strings.Replace(valid, "\"candidate_sha\"", "\"Candidate_SHA\"", 1),
		"missing":   strings.Replace(valid, "  \"rollback_tag\": \"v0.2.0\",\n", "", 1),
		"trailing":  valid + "{}\n",
		"non-string": strings.Replace(valid,
			"\"candidate_binary_sha256\": \""+strings.Repeat("b", 64)+"\"",
			"\"candidate_binary_sha256\": 7", 1),
	}
	for name, contents := range variants {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRollbackInputLock([]byte(contents)); err == nil {
				t.Fatalf("parseRollbackInputLock accepted %s input", name)
			}
		})
	}
}

func TestRollbackInputLockRejectsFixedIdentityAndMetadataViolations(t *testing.T) {
	valid := string(validRollbackInputLockJSON())
	variants := map[string]string{
		"rollback tag": strings.Replace(valid, "\"rollback_tag\": \"v0.2.0\"", "\"rollback_tag\": \"v0.2.0-moved\"", 1),
		"rollback sha": strings.Replace(valid, rollbackV020SHA, strings.Repeat("f", 40), 1),
		"provenance":   strings.Replace(valid, "https://evidence.example/candidate.intoto.jsonl", "relative-provenance", 1),
		"trust policy": strings.Replace(valid, "https://trust.example/policy/v1.json", "policy.json", 1),
		"builder":      strings.Replace(valid, "https://builder.example/workflows/release@v1", "builder with spaces", 1),
		"created at":   strings.Replace(valid, "2026-08-20T00:00:00Z", "2026-08-20 00:00:00", 1),
	}
	for name, contents := range variants {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRollbackInputLock([]byte(contents)); err == nil {
				t.Fatalf("parseRollbackInputLock accepted invalid %s", name)
			}
		})
	}
}

func TestRollbackInputLockRejectsAmbiguousTrustPolicyAuthorityUserinfoAndFragment(t *testing.T) {
	valid := string(validRollbackInputLockJSON())
	const original = "https://trust.example/policy/v1.json"
	variants := []struct {
		name      string
		reference string
	}{
		{name: "empty hostname with port", reference: "https://:443/policy/v1.json"},
		{name: "userinfo", reference: "https://release-owner@trust.example/policy/v1.json"},
		{name: "fragment", reference: "https://trust.example/policy/v1.json#approved"},
	}
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			contents := strings.Replace(valid, original, variant.reference, 1)
			if _, err := parseRollbackInputLock([]byte(contents)); err == nil {
				t.Fatalf("parseRollbackInputLock accepted trust policy URI %q", variant.reference)
			}
		})
	}
}

func TestRollbackInputLockRestrictsProvenanceAndBuilderReferencesToSafeSchemes(t *testing.T) {
	valid := string(validRollbackInputLockJSON())
	fields := []struct {
		name     string
		original string
	}{
		{name: "candidate provenance", original: "https://evidence.example/candidate.intoto.jsonl"},
		{name: "rollback provenance", original: "https://evidence.example/v0.2.0.intoto.jsonl"},
		{name: "builder identity", original: "https://builder.example/workflows/release@v1"},
	}
	unsafeReferences := []struct {
		name      string
		reference string
	}{
		{name: "file", reference: "file://evidence.example/release"},
		{name: "javascript", reference: "javascript://evidence.example/release"},
		{name: "data", reference: "data://evidence.example/release"},
		{name: "empty HTTPS hostname", reference: "https://:443/release"},
		{name: "HTTPS userinfo", reference: "https://release-owner@evidence.example/release"},
		{name: "HTTPS fragment", reference: "https://evidence.example/release#mutable-view"},
		{name: "empty URN opaque", reference: "urn:"},
		{name: "URN fragment", reference: "urn:example:aegis:release#mutable-view"},
	}
	for _, field := range fields {
		for _, unsafe := range unsafeReferences {
			t.Run(field.name+"/"+unsafe.name, func(t *testing.T) {
				contents := strings.Replace(valid, field.original, unsafe.reference, 1)
				if _, err := parseRollbackInputLock([]byte(contents)); err == nil {
					t.Fatalf("parseRollbackInputLock accepted unsafe %s reference %q", field.name, unsafe.reference)
				}
			})
		}
	}
}

func TestRollbackInputLockAcceptsHTTPSAuthoritiesAndNonemptyOpaqueURNReferences(t *testing.T) {
	valid := string(validRollbackInputLockJSON())
	valid = strings.Replace(valid,
		"https://evidence.example/candidate.intoto.jsonl",
		"urn:example:aegis:provenance:candidate", 1)
	valid = strings.Replace(valid,
		"https://evidence.example/v0.2.0.intoto.jsonl",
		"urn:example:aegis:provenance:v0.2.0", 1)
	valid = strings.Replace(valid,
		"https://builder.example/workflows/release@v1",
		"urn:example:aegis:builder:release-v1", 1)
	if _, err := parseRollbackInputLock([]byte(valid)); err != nil {
		t.Fatalf("parseRollbackInputLock rejected safe HTTPS/URN reference contract: %v", err)
	}
}

func TestRollbackInputLockRejectsInvalidUTF8SurrogatesReplacementAndUnicodeConfusables(t *testing.T) {
	valid := string(validRollbackInputLockJSON())
	invalidUTF8 := []byte(valid)
	referenceOffset := bytes.Index(invalidUTF8, []byte("evidence.example/candidate"))
	if referenceOffset < 0 {
		t.Fatal("valid lock fixture is missing candidate provenance reference")
	}
	invalidUTF8[referenceOffset] = 0xff
	variants := map[string][]byte{
		"raw invalid UTF-8": invalidUTF8,
		"lone surrogate": []byte(strings.Replace(valid,
			"https://evidence.example/candidate.intoto.jsonl",
			`https://evidence.example/\ud800.intoto.jsonl`, 1)),
		"replacement character": []byte(strings.Replace(valid,
			"https://evidence.example/candidate.intoto.jsonl",
			"https://evidence.example/\ufffd.intoto.jsonl", 1)),
		"Unicode confusable": []byte(strings.Replace(valid,
			"https://evidence.example/candidate.intoto.jsonl",
			"https://evidence。example/candidate.intoto.jsonl", 1)),
	}
	for name, contents := range variants {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRollbackInputLock(contents); err == nil {
				t.Fatalf("parseRollbackInputLock accepted %s input", name)
			}
		})
	}
}

func TestRollbackInputLockFileRejectsSymlinkFIFOUnsafeModeAndOversize(t *testing.T) {
	root := t.TempDir()
	data := validRollbackInputLockJSON()
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	validPath := filepath.Join(root, "valid.json")
	if err := os.WriteFile(validPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(validPath, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadRollbackInputLock(link, digest); err == nil {
		t.Fatal("loadRollbackInputLock accepted symlink")
	}
	unsafePath := filepath.Join(root, "unsafe.json")
	if err := os.WriteFile(unsafePath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadRollbackInputLock(unsafePath, digest); err == nil {
		t.Fatal("loadRollbackInputLock accepted unsafe permissions")
	}
	oversized := filepath.Join(root, "oversized.json")
	oversizedData := bytes.Repeat([]byte{'x'}, maxRollbackInputLockBytes+1)
	if err := os.WriteFile(oversized, oversizedData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadRollbackInputLock(oversized, fmt.Sprintf("%x", sha256.Sum256(oversizedData))); err == nil {
		t.Fatal("loadRollbackInputLock accepted oversized input")
	}
	fifo := filepath.Join(root, "lock.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := loadRollbackInputLock(fifo, digest)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("loadRollbackInputLock accepted FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("loadRollbackInputLock blocked on FIFO")
	}
}

func TestDrillEnvironmentDoesNotInheritHostSecrets(t *testing.T) {
	t.Setenv("CANARY_HOST_SECRET", "must-not-enter-child")
	secrets := &drillSecrets{
		master: bytes.Repeat([]byte{1}, 32), jwt: bytes.Repeat([]byte{2}, 32), provider: bytes.Repeat([]byte{3}, 32),
	}
	env := drillEnvironment(secrets, "/drill/ca.pem", "/drill/tmp")
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "CANARY_HOST_SECRET") || strings.Contains(joined, "must-not-enter-child") {
		t.Fatalf("child environment inherited host canary: %q", joined)
	}
	for _, required := range []string{drillMasterKeyEnv + "=", drillJWTKeyEnv + "=", "SSL_CERT_FILE=/drill/ca.pem", "TMPDIR=/drill/tmp"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("child environment missing %q: %q", required, joined)
		}
	}
}

func TestNewDrillSecretsProviderCredentialIsHeaderSafeHighEntropyHex(t *testing.T) {
	seen := make(map[[sha256.Size]byte]struct{}, 64)
	for iteration := 0; iteration < 64; iteration++ {
		secrets, err := newDrillSecrets()
		if err != nil {
			t.Fatal(err)
		}
		if len(secrets.provider) != 64 {
			t.Fatalf("provider credential length = %d, want 64 hex bytes", len(secrets.provider))
		}
		for _, character := range secrets.provider {
			if !strings.ContainsRune("0123456789abcdef", rune(character)) {
				utils.MemZero(secrets.master)
				utils.MemZero(secrets.jwt)
				utils.MemZero(secrets.provider)
				t.Fatalf("provider credential contains non-header-safe byte %#x", character)
			}
		}
		value := sha256.Sum256(secrets.provider)
		if _, duplicate := seen[value]; duplicate {
			utils.MemZero(secrets.master)
			utils.MemZero(secrets.jwt)
			utils.MemZero(secrets.provider)
			t.Fatal("provider credential repeated across independent generation")
		}
		seen[value] = struct{}{}
		utils.MemZero(secrets.master)
		utils.MemZero(secrets.jwt)
		utils.MemZero(secrets.provider)
		for _, secret := range [][]byte{secrets.master, secrets.jwt, secrets.provider} {
			for _, value := range secret {
				if value != 0 {
					t.Fatal("drill secret was not zeroed")
				}
			}
		}
	}
}

func TestRequireAuthRejectionsChecksMissingAndMalformedBeforeProvider(t *testing.T) {
	var authorizations []string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		authorizations = append(authorizations, request.Header.Get("Authorization"))
		return testHTTPResponse(http.StatusUnauthorized), nil
	})}

	provider := &fakeProvider{}
	if err := requireAuthRejections(context.Background(), client, "http://gateway.example", provider); err != nil {
		t.Fatalf("requireAuthRejections: %v", err)
	}
	want := []string{"", "Bearer malformed"}
	if fmt.Sprint(authorizations) != fmt.Sprint(want) {
		t.Fatalf("Authorization values = %q, want %q", authorizations, want)
	}
	if provider.hits.Load() != 0 {
		t.Fatalf("provider hits = %d, want 0", provider.hits.Load())
	}
	if provider.attempts.Load() != 0 {
		t.Fatalf("provider attempts = %d, want 0", provider.attempts.Load())
	}
}

func TestRequireAuthRejectionsFailsClosedOnAcceptedOrForwardedRequest(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return testHTTPResponse(http.StatusOK), nil
		})}
		if err := requireAuthRejections(context.Background(), client, "http://gateway.example", &fakeProvider{}); err == nil {
			t.Fatal("requireAuthRejections accepted a 200 response")
		}
	})

	t.Run("wrong provider authorization returned upstream 401", func(t *testing.T) {
		provider := &fakeProvider{}
		client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			provider.attempts.Add(1)
			return testHTTPResponse(http.StatusUnauthorized), nil
		})}
		if err := requireAuthRejections(context.Background(), client, "http://gateway.example", provider); err == nil {
			t.Fatal("requireAuthRejections accepted a request that reached the provider and received an upstream 401")
		}
		if provider.attempts.Load() != 1 || provider.hits.Load() != 0 {
			t.Fatalf("provider counters = attempts:%d hits:%d, want attempts:1 hits:0", provider.attempts.Load(), provider.hits.Load())
		}
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testHTTPResponse(status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader("response")),
		Header:     make(http.Header),
	}
}

func TestDigestMatchesRequiresExactExpectedSHA256(t *testing.T) {
	digest := strings.Repeat("a", 64)
	if !digestMatches(digest, digest) {
		t.Fatal("digestMatches rejected exact expected digest")
	}
	if digestMatches(digest, strings.Repeat("b", 64)) || digestMatches(digest, "a") {
		t.Fatal("digestMatches accepted a mismatched or short expected digest")
	}
}

func TestRunBoundedProcessKillsWholeGroupOnTimeout(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "orphan-marker")
	binary := filepath.Join(root, "forking-fixture")
	script := "#!/bin/sh\n" +
		"(sleep 1; printf orphan > \"$1\") &\n" +
		"sleep 30\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, marker)
	_, _, err := runBoundedCommand(context.Background(), 100*time.Millisecond, cmd, identityEnvironment())
	if err == nil {
		t.Fatal("runBoundedCommand succeeded despite timeout")
	}
	time.Sleep(2 * time.Second)
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("timed-out process left an orphan child; marker stat error = %v", statErr)
	}
}

func TestRunBoundedCommandRejectsOutputOverflow(t *testing.T) {
	cmd := exec.Command("/usr/bin/head", "-c", strconv.Itoa(maxChildOutputBytes+1), "/dev/zero")
	stdout, stderr, err := runBoundedCommand(context.Background(), time.Second, cmd, identityEnvironment())
	if err == nil {
		t.Fatalf("runBoundedCommand silently accepted truncated output: stdout=%d stderr=%d", len(stdout), len(stderr))
	}
	if len(stdout) > maxChildOutputBytes || len(stderr) > maxChildOutputBytes {
		t.Fatalf("bounded output exceeded cap: stdout=%d stderr=%d", len(stdout), len(stderr))
	}
}

func TestGatewayStopKillsIgnoringSameGroupDescendantAfterDirectChildExit(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "descendant-marker")
	ready := filepath.Join(root, "descendant-ready")
	pidFile := filepath.Join(root, "descendant-pid")
	trigger := filepath.Join(root, "descendant-trigger")
	cmd := exec.Command(os.Args[0], "-test.run=^TestGatewayDescendantHelperProcess$")
	cmd.Env = append(identityEnvironment(),
		"AEGIS_TEST_GATEWAY_HELPER=1",
		"AEGIS_TEST_MARKER="+marker,
		"AEGIS_TEST_READY="+ready,
		"AEGIS_TEST_PID_FILE="+pidFile,
		"AEGIS_TEST_TRIGGER="+trigger,
	)
	process := startGatewayProcessForTest(t, cmd)
	t.Cleanup(func() { _ = syscall.Kill(-process.cmd.Process.Pid, syscall.SIGKILL) })
	deadline := time.Now().Add(time.Second)
	var childPID int
	var lastPIDErr error
	for {
		_, readyErr := os.Stat(ready)
		if readyErr == nil {
			pidData, readErr := os.ReadFile(pidFile)
			if readErr == nil {
				parsedPID, parseErr := strconv.Atoi(string(pidData))
				if parseErr == nil && parsedPID > 0 {
					childPID = parsedPID
					break
				}
				lastPIDErr = parseErr
				if parseErr == nil {
					lastPIDErr = fmt.Errorf("invalid descendant PID %d", parsedPID)
				}
			} else if !errors.Is(readErr, os.ErrNotExist) {
				t.Fatalf("read descendant PID: %v", readErr)
			}
		} else if !errors.Is(readyErr, os.ErrNotExist) {
			t.Fatalf("stat descendant readiness: %v", readyErr)
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway descendant did not become ready: last PID error: %v", lastPIDErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	childPGID, err := syscall.Getpgid(childPID)
	if err != nil {
		t.Fatal(err)
	}
	if childPGID != process.cmd.Process.Pid {
		t.Fatalf("fixture child PGID = %d, want gateway PGID %d", childPGID, process.cmd.Process.Pid)
	}
	if err := process.stop(); err != nil {
		t.Fatalf("gateway stop: %v", err)
	}
	// A killed orphan may remain as a zombie until the external PID 1 reaps it;
	// kill(pid, 0) therefore cannot distinguish an executing descendant from a
	// terminated-but-unreaped one. Prove the security property directly: the
	// TERM-ignoring descendant must no longer be able to reach its delayed write.
	if err := os.WriteFile(trigger, []byte("continue"), 0o600); err != nil {
		t.Fatalf("write descendant trigger: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		_, markerErr := os.Stat(marker)
		if markerErr == nil {
			t.Fatal("gateway stop left same-group descendant executable")
		}
		if !errors.Is(markerErr, os.ErrNotExist) {
			t.Fatalf("stat descendant marker: %v", markerErr)
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestGatewayDescendantHelperProcess(t *testing.T) {
	if os.Getenv("AEGIS_TEST_GATEWAY_HELPER") != "1" {
		return
	}
	marker := os.Getenv("AEGIS_TEST_MARKER")
	ready := os.Getenv("AEGIS_TEST_READY")
	pidFile := os.Getenv("AEGIS_TEST_PID_FILE")
	trigger := os.Getenv("AEGIS_TEST_TRIGGER")
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	child := exec.Command("/bin/sh", "-c", "trap '' TERM; printf ready > \"$2\"; while [ ! -f \"$3\" ]; do sleep 0.05; done; printf orphan > \"$1\"", "fixture", marker, ready, trigger)
	child.Env = identityEnvironment()
	if err := child.Start(); err != nil {
		os.Exit(91)
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
		os.Exit(92)
	}
	<-signals
	os.Exit(0)
}

func startGatewayProcessForTest(t *testing.T, cmd *exec.Cmd) *gatewayProcess {
	t.Helper()
	process := &gatewayProcess{cmd: cmd, done: make(chan struct{})}
	if len(process.cmd.Env) == 0 {
		process.cmd.Env = identityEnvironment()
	}
	process.cmd.Stdout = &process.stdout
	process.cmd.Stderr = &process.stderr
	process.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := process.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		err := process.cmd.Wait()
		process.waitMu.Lock()
		process.waitErr = err
		process.waitMu.Unlock()
		close(process.done)
	}()
	return process
}

func TestForgedVersionScriptCannotSatisfyAegisBuildIdentity(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "forged-aegis")
	sha := strings.Repeat("a", 40)
	script := "#!/bin/sh\n" +
		"printf '%s\\n' 'aegis v0.2.0 (commit: " + sha + ", built: forged)'\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "--version")
	stdout, _, err := runBoundedCommand(context.Background(), time.Second, cmd, identityEnvironment())
	if err != nil || !strings.Contains(stdout, sha) {
		t.Fatalf("forged version fixture did not forge expected stdout: stdout=%q err=%v", stdout, err)
	}
	file, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := validateAegisBuildInfoReader(file, sha, false); err == nil {
		t.Fatal("script with forged --version output satisfied Go build identity")
	}
}

func TestValidateAegisBuildInfoRejectsWrongRevisionDirtyOrModule(t *testing.T) {
	sha := strings.Repeat("a", 40)
	valid := func() *debug.BuildInfo {
		return &debug.BuildInfo{
			Path: aegisMainPackagePath,
			Main: debug.Module{Path: aegisModulePath},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: sha},
				{Key: "vcs.modified", Value: "false"},
			},
		}
	}
	for name, mutate := range map[string]func(*debug.BuildInfo){
		"wrong revision": func(info *debug.BuildInfo) { info.Settings[0].Value = strings.Repeat("b", 40) },
		"dirty":          func(info *debug.BuildInfo) { info.Settings[1].Value = "true" },
		"wrong main":     func(info *debug.BuildInfo) { info.Path = "example.invalid/cmd/aegis" },
		"wrong module":   func(info *debug.BuildInfo) { info.Main.Path = "example.invalid/AegisLLM" },
	} {
		t.Run(name, func(t *testing.T) {
			info := valid()
			mutate(info)
			if err := validateAegisBuildInfo(info, sha, false); err == nil {
				t.Fatalf("validateAegisBuildInfo accepted %s", name)
			}
		})
	}
	if err := validateAegisBuildInfo(valid(), sha, false); err != nil {
		t.Fatalf("validateAegisBuildInfo rejected bound identity: %v", err)
	}
}

func TestValidateVersionOutputRequiresOneExactStableLine(t *testing.T) {
	sha := strings.Repeat("a", 40)
	valid := "aegis v0.2.0 (commit: " + sha + ", built: 2026-08-20T00:00:00Z)\n"
	if err := validateVersionOutput(valid, "v0.2.0", sha); err != nil {
		t.Fatalf("validateVersionOutput rejected stable output: %v", err)
	}
	for name, output := range map[string]string{
		"prefix":     "forged " + valid,
		"suffix":     strings.TrimSuffix(valid, "\n") + " forged\n",
		"multiline":  "attacker\n" + valid,
		"blank line": valid + "\n",
		"no newline": strings.TrimSuffix(valid, "\n"),
		"bad built":  strings.Replace(valid, "2026-08-20T00:00:00Z", "date with spaces", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateVersionOutput(output, "v0.2.0", sha); err == nil {
				t.Fatalf("validateVersionOutput accepted %s output %q", name, output)
			}
		})
	}
}

func TestBuildInfoReaderRejectsNonGoPayload(t *testing.T) {
	file, err := os.Open(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		_ = file.Close()
		t.Fatal("unexpectedly opened missing fixture")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("open error = %v, want not exist", err)
	}
	if _, err := buildinfo.Read(bytes.NewReader([]byte("not a Go executable"))); err == nil {
		t.Fatal("debug/buildinfo accepted a non-Go payload")
	}
}

func TestValidateCandidateIdentityRejectsShortSHA(t *testing.T) {
	repo := initTestRepository(t, false)
	err := validateCandidateIdentity(repo, "deadbeef", false)
	if err == nil || !strings.Contains(err.Error(), "40 lowercase hexadecimal") {
		t.Fatalf("validateCandidateIdentity error = %v, want full-SHA rejection", err)
	}
}

func TestValidateCandidateIdentityRejectsDirtyRepository(t *testing.T) {
	repo := initTestRepository(t, true)
	sha := gitOutputT(t, repo, "rev-parse", "HEAD")
	err := validateCandidateIdentity(repo, sha, false)
	if err == nil || !strings.Contains(err.Error(), "not clean") {
		t.Fatalf("validateCandidateIdentity error = %v, want dirty-repository rejection", err)
	}
}

func TestValidateCandidateIdentityMarksExplicitDirtyOverrideIterationOnly(t *testing.T) {
	repo := initTestRepository(t, true)
	sha := gitOutputT(t, repo, "rev-parse", "HEAD")
	identity, err := inspectCandidateIdentity(repo, sha, true)
	if err != nil {
		t.Fatalf("inspectCandidateIdentity: %v", err)
	}
	if identity.EvidenceClass != evidenceIterationOnly || !identity.Dirty {
		t.Fatalf("identity = %+v, want dirty ITERATION_ONLY", identity)
	}
}

func TestInspectCandidateIdentityDoesNotTrustAmbientPATHGit(t *testing.T) {
	repo := initEmptyTestRepository(t)
	sha := gitOutputT(t, repo, "rev-parse", "HEAD")
	marker := filepath.Join(t.TempDir(), "fake-git-executed")
	fakeBin := t.TempDir()
	fakeGit := filepath.Join(fakeBin, "git")
	script := "#!/bin/sh\nprintf executed > " + strconv.Quote(marker) + "\nexec /usr/bin/git \"$@\"\n"
	if err := os.WriteFile(fakeGit, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake git: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	identity, err := inspectCandidateIdentityContext(context.Background(), repo, sha, false)
	if err != nil {
		t.Fatalf("inspectCandidateIdentityContext rejected a canonical empty repository: %v", err)
	}
	if identity.Dirty || identity.EvidenceClass != evidenceFinal {
		t.Fatalf("identity = %+v, want clean FINAL_CANDIDATE", identity)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("inspectCandidateIdentityContext executed ambient-PATH git")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat fake-git marker: %v", err)
	}
}

func TestInspectCandidateIdentityRejectsTrackedChangesHiddenByIndexFlags(t *testing.T) {
	for _, flag := range []string{"--assume-unchanged", "--skip-worktree"} {
		t.Run(flag, func(t *testing.T) {
			repo := initTestRepository(t, false)
			sha := gitOutputT(t, repo, "rev-parse", "HEAD")
			baseline, err := inspectCandidateIdentityContext(context.Background(), repo, sha, false)
			if err != nil {
				t.Fatalf("clean baseline rejected before %s fixture: %v", flag, err)
			}
			if baseline.Dirty || baseline.EvidenceClass != evidenceFinal {
				t.Fatalf("clean baseline = %+v, want FINAL_CANDIDATE", baseline)
			}
			runGit(t, repo, "update-index", flag, "tracked")
			if err := os.WriteFile(filepath.Join(repo, "tracked"), []byte("hidden dirty content\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			if _, err := inspectCandidateIdentityContext(context.Background(), repo, sha, false); err == nil || !strings.Contains(err.Error(), "not clean") {
				t.Fatalf("inspectCandidateIdentityContext accepted a tracked change hidden by %s", flag)
			}
		})
	}
}

func TestInspectCandidateIdentityRejectsCoreWorktreeRedirection(t *testing.T) {
	repo := initEmptyTestRepository(t)
	sha := gitOutputT(t, repo, "rev-parse", "HEAD")
	redirectedWorktree := t.TempDir()
	runGit(t, repo, "config", "core.worktree", redirectedWorktree)
	if err := os.WriteFile(filepath.Join(repo, "untracked"), []byte("dirty but hidden by core.worktree\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := inspectCandidateIdentityContext(context.Background(), repo, sha, false); err == nil {
		t.Fatal("inspectCandidateIdentityContext trusted a repository-local core.worktree redirection")
	}
}

func TestInspectCandidateIdentityRejectsReplacementRefs(t *testing.T) {
	repo := initTestRepository(t, false)
	candidateSHA := gitOutputT(t, repo, "rev-parse", "HEAD")
	runGit(t, repo, "rm", "-q", "tracked")
	runGit(t, repo, "commit", "-q", "-m", "replacement fixture")
	replacementSHA := gitOutputT(t, repo, "rev-parse", "HEAD")
	runGit(t, repo, "reset", "--hard", candidateSHA)
	if err := os.Remove(filepath.Join(repo, "tracked")); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "replace", candidateSHA, replacementSHA)

	if _, err := inspectCandidateIdentityContext(context.Background(), repo, candidateSHA, false); err == nil {
		t.Fatal("inspectCandidateIdentityContext trusted a repository-local replacement ref")
	}
}

func TestInspectCandidateIdentityRejectsRepositoryLocalContentFiltersWithoutExecutingThem(t *testing.T) {
	for _, filterKind := range []string{"clean", "process"} {
		t.Run(filterKind, func(t *testing.T) {
			repo := initTestRepository(t, false)
			candidateSHA := gitOutputT(t, repo, "rev-parse", "HEAD")
			marker := configureRepositoryLocalContentFilter(t, repo, filterKind)
			if err := os.WriteFile(filepath.Join(repo, "tracked"), []byte("dirty but hidden by filter\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			_, identityErr := inspectCandidateIdentityContext(context.Background(), repo, candidateSHA, false)
			_, markerErr := os.Stat(marker)
			if identityErr == nil {
				t.Error("inspectCandidateIdentityContext trusted a repository-local content filter")
			}
			if markerErr == nil {
				t.Error("inspectCandidateIdentityContext executed a repository-local content filter")
			} else if !errors.Is(markerErr, os.ErrNotExist) {
				t.Fatalf("stat content-filter marker: %v", markerErr)
			}
		})
	}
}

func TestInspectCandidateIdentityAcceptsCleanTreeWithoutExecutingRepositoryLocalContentFilters(t *testing.T) {
	for _, filterKind := range []string{"clean", "process"} {
		t.Run(filterKind, func(t *testing.T) {
			repo := initTestRepository(t, false)
			candidateSHA := gitOutputT(t, repo, "rev-parse", "HEAD")
			marker := configureRepositoryLocalContentFilter(t, repo, filterKind)

			identity, identityErr := inspectCandidateIdentityContext(context.Background(), repo, candidateSHA, false)
			_, markerErr := os.Stat(marker)
			if identityErr != nil {
				t.Errorf("inspectCandidateIdentityContext rejected a clean tree: %v", identityErr)
			} else if identity.Dirty || identity.EvidenceClass != evidenceFinal {
				t.Errorf("clean identity = %+v, want FINAL_CANDIDATE", identity)
			}
			if markerErr == nil {
				t.Error("inspectCandidateIdentityContext executed a repository-local content filter")
			} else if !errors.Is(markerErr, os.ErrNotExist) {
				t.Fatalf("stat content-filter marker: %v", markerErr)
			}
		})
	}
}

func configureRepositoryLocalContentFilter(t *testing.T, repo, filterKind string) string {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "filter-executed")
	driver := "rollback-drill-identity-filter"
	attributes := filepath.Join(repo, ".git", "info", "attributes")
	if err := os.WriteFile(attributes, []byte("tracked filter="+driver+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	switch filterKind {
	case "clean":
		filter := filepath.Join(t.TempDir(), "clean-filter")
		script := "#!/bin/sh\nprintf executed > " + strconv.Quote(marker) + "\nprintf 'clean\\n'\n"
		if err := os.WriteFile(filter, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		runGit(t, repo, "config", "filter."+driver+".clean", filter)
	case "process":
		filter := filepath.Join(t.TempDir(), "process-filter")
		script := "#!/bin/sh\n" +
			"printf executed > " + strconv.Quote(marker) + "\n" +
			"export AEGIS_TEST_GIT_PROCESS_FILTER=1\n" +
			"export AEGIS_TEST_FILTER_MARKER=" + strconv.Quote(marker) + "\n" +
			"exec " + strconv.Quote(os.Args[0]) + " -test.run=^TestGitProcessFilterHelperProcess$\n"
		if err := os.WriteFile(filter, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		runGit(t, repo, "config", "filter."+driver+".process", filter)
	default:
		t.Fatalf("unsupported filter fixture %q", filterKind)
	}
	runGit(t, repo, "config", "filter."+driver+".required", "true")
	return marker
}

func TestInspectCandidateIdentityAcceptsCanonicalEmptyAndTrackedRepositories(t *testing.T) {
	tests := []struct {
		name string
		init func(*testing.T) string
	}{
		{name: "empty", init: initEmptyTestRepository},
		{name: "tracked", init: func(t *testing.T) string { return initTestRepository(t, false) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := tt.init(t)
			sha := gitOutputT(t, repo, "rev-parse", "HEAD")
			identity, err := inspectCandidateIdentityContext(context.Background(), repo, sha, false)
			if err != nil {
				t.Fatalf("inspectCandidateIdentityContext rejected canonical repository: %v", err)
			}
			if identity.Dirty || identity.EvidenceClass != evidenceFinal {
				t.Fatalf("identity = %+v, want clean FINAL_CANDIDATE", identity)
			}
		})
	}
}

func TestInspectCandidateIdentityRejectsIgnoredExtraFiles(t *testing.T) {
	repo := initEmptyTestRepository(t)
	sha := gitOutputT(t, repo, "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(repo, ".git", "info", "exclude"), []byte("ignored-extra\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "ignored-extra"), []byte("must be part of raw identity\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectCandidateIdentityContext(context.Background(), repo, sha, false); err == nil || !strings.Contains(err.Error(), "not clean") {
		t.Fatalf("inspectCandidateIdentityContext ignored an extra worktree file: %v", err)
	}
}

func TestInspectCandidateIdentityRejectsFIFOEvenForDirtyIteration(t *testing.T) {
	repo := initEmptyTestRepository(t)
	sha := gitOutputT(t, repo, "rev-parse", "HEAD")
	if err := syscall.Mkfifo(filepath.Join(repo, "blocking-input"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := inspectCandidateIdentityContext(ctx, repo, sha, true); err == nil {
		t.Fatal("inspectCandidateIdentityContext downgraded a special-file worktree to ITERATION_ONLY")
	}
}

func TestInspectCandidateIdentityRejectsUnsafeGitLayoutsEvenForDirtyIteration(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T) (string, string)
	}{
		{
			name: "symlink git directory",
			setup: func(t *testing.T) (string, string) {
				repo := initEmptyTestRepository(t)
				sha := gitOutputT(t, repo, "rev-parse", "HEAD")
				relocated := filepath.Join(t.TempDir(), "gitdir")
				if err := os.Rename(filepath.Join(repo, ".git"), relocated); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(relocated, filepath.Join(repo, ".git")); err != nil {
					t.Fatal(err)
				}
				return repo, sha
			},
		},
		{
			name: "linked worktree gitfile",
			setup: func(t *testing.T) (string, string) {
				source := initEmptyTestRepository(t)
				sha := gitOutputT(t, source, "rev-parse", "HEAD")
				linked := filepath.Join(t.TempDir(), "linked")
				runGit(t, source, "worktree", "add", "-q", "--detach", linked, sha)
				return linked, sha
			},
		},
		{
			name: "bare repository",
			setup: func(t *testing.T) (string, string) {
				source := initEmptyTestRepository(t)
				sha := gitOutputT(t, source, "rev-parse", "HEAD")
				bare := filepath.Join(t.TempDir(), "bare.git")
				runGit(t, filepath.Dir(bare), "clone", "-q", "--bare", source, bare)
				return bare, sha
			},
		},
		{
			name: "group-writable git directory",
			setup: func(t *testing.T) (string, string) {
				repo := initEmptyTestRepository(t)
				sha := gitOutputT(t, repo, "rev-parse", "HEAD")
				if err := os.Chmod(filepath.Join(repo, ".git"), 0o770); err != nil {
					t.Fatal(err)
				}
				return repo, sha
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, sha := tt.setup(t)
			if _, err := inspectCandidateIdentityContext(context.Background(), repo, sha, true); err == nil {
				t.Fatal("inspectCandidateIdentityContext downgraded an unsafe Git layout to ITERATION_ONLY")
			}
		})
	}
}

func TestInspectCandidateIdentityRejectsSubmodulesEvenForDirtyIteration(t *testing.T) {
	repo := initEmptyTestRepository(t)
	objectSHA := gitOutputT(t, repo, "rev-parse", "HEAD")
	runGit(t, repo, "update-index", "--add", "--cacheinfo", "160000,"+objectSHA+",submodule")
	runGit(t, repo, "commit", "-q", "-m", "gitlink fixture")
	candidateSHA := gitOutputT(t, repo, "rev-parse", "HEAD")

	if _, err := inspectCandidateIdentityContext(context.Background(), repo, candidateSHA, true); err == nil {
		t.Fatal("inspectCandidateIdentityContext downgraded a submodule tree to ITERATION_ONLY")
	}
}

func TestInspectCandidateIdentityAcceptsExecutableAndSymlinkEntries(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "executable",
			setup: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, path string) {
				if err := os.Symlink("literal-target", path); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := initEmptyTestRepository(t)
			tt.setup(t, filepath.Join(repo, "tracked"))
			runGit(t, repo, "add", "tracked")
			runGit(t, repo, "commit", "-q", "-m", tt.name+" fixture")
			sha := gitOutputT(t, repo, "rev-parse", "HEAD")

			identity, err := inspectCandidateIdentityContext(context.Background(), repo, sha, false)
			if err != nil {
				t.Fatalf("inspectCandidateIdentityContext rejected canonical %s entry: %v", tt.name, err)
			}
			if identity.Dirty || identity.EvidenceClass != evidenceFinal {
				t.Fatalf("identity = %+v, want clean FINAL_CANDIDATE", identity)
			}
		})
	}
}

func TestInspectCandidateIdentityBindsExactDirtyWorktreeAcrossChecks(t *testing.T) {
	repo := initTestRepository(t, false)
	sha := gitOutputT(t, repo, "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(repo, "tracked"), []byte("first dirty state\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := inspectCandidateIdentityContext(context.Background(), repo, sha, true)
	if err != nil {
		t.Fatalf("inspect first dirty identity: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "tracked"), []byte("second dirty state\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := inspectCandidateIdentityContext(context.Background(), repo, sha, true)
	if err != nil {
		t.Fatalf("inspect second dirty identity: %v", err)
	}
	if first == second {
		t.Fatalf("distinct dirty worktrees produced the same identity: %+v", first)
	}
}

func TestInspectCandidateIdentityRejectsPromisorRepositoryWithoutRunningRemoteHelper(t *testing.T) {
	repo := initTestRepository(t, false)
	candidateSHA := gitOutputT(t, repo, "rev-parse", "HEAD")
	blobSHA := gitOutputT(t, repo, "rev-parse", "HEAD:tracked")
	if err := os.Remove(filepath.Join(repo, ".git", "objects", blobSHA[:2], blobSHA[2:])); err != nil {
		t.Fatalf("remove promised blob fixture: %v", err)
	}
	marker := filepath.Join(t.TempDir(), "remote-helper-executed")
	helper := filepath.Join(t.TempDir(), "promisor-remote-helper")
	script := "#!/bin/sh\nprintf executed > " + strconv.Quote(marker) + "\nexit 1\n"
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatalf("write promisor helper: %v", err)
	}
	runGit(t, repo, "config", "protocol.ext.allow", "always")
	runGit(t, repo, "config", "remote.origin.url", "ext::"+helper)
	runGit(t, repo, "config", "remote.origin.promisor", "true")
	runGit(t, repo, "config", "core.repositoryFormatVersion", "1")
	runGit(t, repo, "config", "extensions.partialClone", "origin")

	if _, err := inspectCandidateIdentityContext(context.Background(), repo, candidateSHA, true); err == nil {
		t.Fatal("inspectCandidateIdentityContext accepted a promisor repository")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("inspectCandidateIdentityContext executed a promisor remote helper")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat promisor-helper marker: %v", err)
	}
}

func TestInspectCandidateIdentityRejectsAlternateObjectDatabase(t *testing.T) {
	repo := initEmptyTestRepository(t)
	candidateSHA := gitOutputT(t, repo, "rev-parse", "HEAD")
	alternates := filepath.Join(repo, ".git", "objects", "info", "alternates")
	if err := os.WriteFile(alternates, []byte(t.TempDir()+"\n"), 0o600); err != nil {
		t.Fatalf("write alternates fixture: %v", err)
	}
	if _, err := inspectCandidateIdentityContext(context.Background(), repo, candidateSHA, true); err == nil {
		t.Fatal("inspectCandidateIdentityContext downgraded an alternate object database to ITERATION_ONLY")
	}
}

func TestInspectCandidateIdentityRejectsUnsafeNestedEntriesEvenForDirtyIteration(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "group-writable regular file",
			setup: func(t *testing.T, repo string) {
				path := filepath.Join(repo, "unsafe")
				if err := os.WriteFile(path, []byte("unsafe\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o660); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "group-writable directory",
			setup: func(t *testing.T, repo string) {
				if err := os.Mkdir(filepath.Join(repo, "unsafe"), 0o770); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Join(repo, "unsafe"), 0o770); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "setuid regular file",
			setup: func(t *testing.T, repo string) {
				path := filepath.Join(repo, "unsafe")
				if err := os.WriteFile(path, []byte("unsafe\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o700|os.ModeSetuid); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "sticky directory",
			setup: func(t *testing.T, repo string) {
				path := filepath.Join(repo, "unsafe")
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o700|os.ModeSticky); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "group-writable worktree root",
			setup: func(t *testing.T, repo string) {
				if err := os.Chmod(repo, 0o770); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	if os.Geteuid() == 0 {
		tests = append(tests, struct {
			name  string
			setup func(*testing.T, string)
		}{
			name: "foreign-owned regular file",
			setup: func(t *testing.T, repo string) {
				path := filepath.Join(repo, "unsafe")
				if err := os.WriteFile(path, []byte("unsafe\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(path, 1, -1); err != nil {
					t.Fatal(err)
				}
			},
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := initEmptyTestRepository(t)
			candidateSHA := gitOutputT(t, repo, "rev-parse", "HEAD")
			tt.setup(t, repo)
			if _, err := inspectCandidateIdentityContext(context.Background(), repo, candidateSHA, true); err == nil {
				t.Fatal("inspectCandidateIdentityContext downgraded an unsafe worktree entry to ITERATION_ONLY")
			}
		})
	}
}

func TestInspectCandidateIdentityRejectsNonSHA1ObjectFormat(t *testing.T) {
	repo := initEmptyTestRepository(t)
	candidateSHA := gitOutputT(t, repo, "rev-parse", "HEAD")
	runGit(t, repo, "config", "core.repositoryFormatVersion", "1")
	runGit(t, repo, "config", "extensions.objectFormat", "sha256")
	if _, err := inspectCandidateIdentityContext(context.Background(), repo, candidateSHA, true); err == nil || !strings.Contains(err.Error(), "object format") {
		t.Fatalf("inspectCandidateIdentityContext object-format error = %v, want fail closed", err)
	}
}

func TestCandidateGitEnvironmentDisablesReplacementAndLazyFetch(t *testing.T) {
	want := map[string]bool{
		"GIT_NO_LAZY_FETCH=1":      false,
		"GIT_NO_REPLACE_OBJECTS=1": false,
		"GIT_TERMINAL_PROMPT=0":    false,
		"PATH=/usr/bin:/bin":       false,
	}
	for _, variable := range candidateGitEnvironment() {
		if seen, required := want[variable]; required {
			if seen {
				t.Fatalf("candidateGitEnvironment contains duplicate %q", variable)
			}
			want[variable] = true
		}
	}
	for variable, seen := range want {
		if !seen {
			t.Errorf("candidateGitEnvironment missing %q", variable)
		}
	}
}

func TestParseCandidateTreeOutputAcceptsCanonicalBlobEntries(t *testing.T) {
	output := append(gitTreeRecord("100644", "blob", strings.Repeat("a", 40), 5, "README.md"),
		gitTreeRecord("100755", "blob", strings.Repeat("b", 40), 12, "cmd/aegis")...)
	output = append(output, gitTreeRecord("120000", "blob", strings.Repeat("c", 40), 14, "current")...)
	entries, err := parseCandidateTreeOutput(output)
	if err != nil {
		t.Fatalf("parseCandidateTreeOutput rejected canonical entries: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("entry count = %d, want 3", len(entries))
	}
}

func TestParseCandidateTreeOutputRejectsMalformedOrUnsafeEntries(t *testing.T) {
	valid := gitTreeRecord("100644", "blob", strings.Repeat("a", 40), 5, "tracked")
	invalidUTF8Path := append([]byte("100644 blob "+strings.Repeat("a", 40)+"       1\t"), 0xff, 0)
	tests := map[string][]byte{
		"missing NUL terminator": valid[:len(valid)-1],
		"empty record":           append([]byte{0}, valid...),
		"missing metadata":       []byte("100644 blob\ttracked\x00"),
		"unsupported mode":       gitTreeRecord("100664", "blob", strings.Repeat("a", 40), 5, "tracked"),
		"submodule":              gitTreeRecord("160000", "commit", strings.Repeat("a", 40), 0, "submodule"),
		"uppercase object":       gitTreeRecord("100644", "blob", strings.Repeat("A", 40), 5, "tracked"),
		"negative size":          []byte("100644 blob " + strings.Repeat("a", 40) + "      -1\ttracked\x00"),
		"absolute path":          gitTreeRecord("100644", "blob", strings.Repeat("a", 40), 5, "/tracked"),
		"parent traversal":       gitTreeRecord("100644", "blob", strings.Repeat("a", 40), 5, "../tracked"),
		"empty path component":   gitTreeRecord("100644", "blob", strings.Repeat("a", 40), 5, "dir//tracked"),
		"dot path component":     gitTreeRecord("100644", "blob", strings.Repeat("a", 40), 5, "dir/./tracked"),
		"git metadata path":      gitTreeRecord("100644", "blob", strings.Repeat("a", 40), 5, ".git/config"),
		"control in path":        gitTreeRecord("100644", "blob", strings.Repeat("a", 40), 5, "line\nbreak"),
		"invalid UTF-8 path":     invalidUTF8Path,
		"duplicate path":         append(append([]byte(nil), valid...), valid...),
		"file-directory conflict": append(
			gitTreeRecord("100644", "blob", strings.Repeat("a", 40), 1, "conflict"),
			gitTreeRecord("100644", "blob", strings.Repeat("b", 40), 1, "conflict/child")...),
	}
	for name, output := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCandidateTreeOutput(output); err == nil {
				t.Fatalf("parseCandidateTreeOutput accepted %s", name)
			}
		})
	}
}

func TestParseCandidateTreeOutputEnforcesOutputEntryPathAndSizeBudgets(t *testing.T) {
	tests := map[string][]byte{
		"output bytes": bytes.Repeat([]byte("x"), maxCandidateTreeOutputBytes+1),
		"path bytes": gitTreeRecord("100644", "blob", strings.Repeat("a", 40), 1,
			strings.Repeat("p", maxCandidatePathBytes+1)),
		"blob bytes": gitTreeRecord("100644", "blob", strings.Repeat("a", 40), maxCandidateBlobBytes+1,
			"oversized"),
	}

	var tooMany []byte
	for i := 0; i <= maxCandidateTreeEntries; i++ {
		tooMany = append(tooMany, gitTreeRecord("100644", "blob", strings.Repeat("a", 40), 0,
			fmt.Sprintf("entry-%05d", i))...)
	}
	tests["entry count"] = tooMany

	for name, output := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCandidateTreeOutput(output); err == nil {
				t.Fatalf("parseCandidateTreeOutput accepted input beyond %s budget", name)
			}
		})
	}
}

func gitTreeRecord(mode, objectType, objectID string, size int64, path string) []byte {
	return []byte(fmt.Sprintf("%s %s %s %7d\t%s\x00", mode, objectType, objectID, size, path))
}

func TestGitProcessFilterHelperProcess(t *testing.T) {
	if os.Getenv("AEGIS_TEST_GIT_PROCESS_FILTER") != "1" {
		return
	}
	if err := os.WriteFile(os.Getenv("AEGIS_TEST_FILTER_MARKER"), []byte("executed"), 0o600); err != nil {
		os.Exit(91)
	}
	if err := serveGitCleanProcessFilter(os.Stdin, os.Stdout); err != nil {
		os.Exit(92)
	}
	os.Exit(0)
}

func serveGitCleanProcessFilter(input io.Reader, output io.Writer) error {
	reader := bufio.NewReader(input)
	writer := bufio.NewWriter(output)
	hello, err := readGitPacketList(reader)
	if err != nil || len(hello) != 2 || string(hello[0]) != "git-filter-client\n" || string(hello[1]) != "version=2\n" {
		return errors.New("invalid filter client handshake")
	}
	if err := writeGitPacketList(writer, []byte("git-filter-server\n"), []byte("version=2\n")); err != nil {
		return err
	}
	if _, err := readGitPacketList(reader); err != nil {
		return err
	}
	if err := writeGitPacketList(writer, []byte("capability=clean\n")); err != nil {
		return err
	}

	for {
		headers, err := readGitPacketList(reader)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		commandClean := false
		for _, header := range headers {
			if string(header) == "command=clean\n" {
				commandClean = true
			}
		}
		if !commandClean {
			return errors.New("unexpected filter command")
		}
		if _, err := readGitPacketList(reader); err != nil {
			return err
		}
		if err := writeGitPacketList(writer, []byte("status=success\n")); err != nil {
			return err
		}
		if err := writeGitPacketList(writer, []byte("clean\n")); err != nil {
			return err
		}
		if _, err := writer.WriteString("0000"); err != nil {
			return err
		}
		if err := writer.Flush(); err != nil {
			return err
		}
	}
}

func readGitPacketList(reader *bufio.Reader) ([][]byte, error) {
	var packets [][]byte
	for {
		prefix := make([]byte, 4)
		if _, err := io.ReadFull(reader, prefix); err != nil {
			if errors.Is(err, io.EOF) && len(packets) == 0 {
				return nil, io.EOF
			}
			return nil, err
		}
		length, err := strconv.ParseUint(string(prefix), 16, 16)
		if err != nil {
			return nil, err
		}
		if length == 0 {
			return packets, nil
		}
		if length < 4 {
			return nil, errors.New("invalid Git packet length")
		}
		payload := make([]byte, int(length)-4)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, err
		}
		packets = append(packets, payload)
	}
}

func writeGitPacketList(writer *bufio.Writer, packets ...[]byte) error {
	for _, packet := range packets {
		if len(packet)+4 > 0xffff {
			return errors.New("Git packet is too large")
		}
		if _, err := fmt.Fprintf(writer, "%04x", len(packet)+4); err != nil {
			return err
		}
		if _, err := writer.Write(packet); err != nil {
			return err
		}
	}
	if _, err := writer.WriteString("0000"); err != nil {
		return err
	}
	return writer.Flush()
}

func TestWriteSummaryIsStableJSONAndContainsNoSecretMaterial(t *testing.T) {
	summary := successSummary{
		SchemaVersion:         3,
		Result:                "PASS",
		EvidenceClass:         evidenceFinal,
		WorktreeClean:         true,
		RunID:                 "019ff59d-b35c-79c1-992c-2b51460e6255",
		ContainmentNonce:      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		StartedAt:             "2026-08-20T00:00:00Z",
		EndedAt:               "2026-08-20T00:10:00Z",
		RunnerBinarySHA256:    strings.Repeat("e", 64),
		CandidateSHA:          strings.Repeat("a", 40),
		RollbackSourceSHA:     rollbackV020SHA,
		CandidateBinarySHA256: strings.Repeat("b", 64),
		RollbackBinarySHA256:  strings.Repeat("c", 64),
		InputLockDigest:       strings.Repeat("d", 64),
		Migration:             "legacy_file_store_to_v2_strict_pass",
		CurrentSmoke:          "health_auth_kms_tls_provider_200_pass",
		Rollback:              "encrypted_backup_restore_v0.2.0_health_auth_kms_tls_provider_200_pass",
	}
	var output bytes.Buffer
	if err := writeSummary(&output, summary); err != nil {
		t.Fatalf("writeSummary: %v", err)
	}
	if strings.Contains(output.String(), drillProviderSecret) || strings.Contains(output.String(), drillJWTSigningKey) {
		t.Fatal("summary contains secret material")
	}
	var decoded successSummary
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("summary is not JSON: %v", err)
	}
	if decoded != summary {
		t.Fatalf("decoded summary = %+v, want %+v", decoded, summary)
	}
	if bytes.Count(output.Bytes(), []byte("\n")) != 1 {
		t.Fatalf("summary = %q, want exactly one JSON line", output.String())
	}
}

func TestWriteSummaryAfterCleanupSuppressesPASSWhenTemporaryCleanupFails(t *testing.T) {
	const root = "/deterministic/drill-root"
	cleanupCalls := 0
	cleanup := func(path string) error {
		cleanupCalls++
		if path != root {
			t.Fatalf("cleanup path = %q, want %q", path, root)
		}
		return errors.New("injected cleanup failure")
	}
	var output bytes.Buffer
	err := writeSummaryAfterCleanup(root, &output, successSummary{Result: "PASS"}, cleanup)
	var staged *stageError
	if !errors.As(err, &staged) || staged.Stage != "cleanup" || staged.Reason != "temporary_cleanup_failed" {
		t.Fatalf("writeSummaryAfterCleanup error = %v, want cleanup: temporary_cleanup_failed", err)
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", cleanupCalls)
	}
	if output.Len() != 0 {
		t.Fatalf("cleanup failure emitted PASS evidence: %q", output.String())
	}
}

func validRollbackInputLockJSON() []byte {
	return []byte(fmt.Sprintf(`{
  "schema": "aegis.rollback-input-lock/v2",
  "run_id": "019ff59d-b35c-79c1-992c-2b51460e6255",
  "containment_nonce": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "candidate_sha": "%s",
  "candidate_binary_sha256": "%s",
  "candidate_provenance_ref": "https://evidence.example/candidate.intoto.jsonl",
  "candidate_provenance_sha256": "%s",
  "rollback_tag": "v0.2.0",
  "rollback_sha": "%s",
  "rollback_binary_sha256": "%s",
  "rollback_provenance_ref": "https://evidence.example/v0.2.0.intoto.jsonl",
  "rollback_provenance_sha256": "%s",
  "runner_binary_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "runner_provenance_ref": "https://evidence.example/rollback-runner.intoto.jsonl",
  "runner_provenance_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
  "trust_policy_uri": "https://trust.example/policy/v1.json",
  "trust_policy_sha256": "%s",
  "builder_identity": "https://builder.example/workflows/release@v1",
  "created_at": "2026-08-20T00:00:00Z"
}
`, strings.Repeat("a", 40), strings.Repeat("b", 64), strings.Repeat("c", 64), rollbackV020SHA,
		strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("f", 64)))
}

func TestCreateLegacyBlobUsesV020NonceCiphertextFormat(t *testing.T) {
	master := bytes.Repeat([]byte{0x41}, 32)
	plaintext := []byte("provider-key-canary")
	blob, err := createLegacyBlob(master, plaintext)
	if err != nil {
		t.Fatalf("createLegacyBlob: %v", err)
	}
	block, err := aes.NewCipher(master)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) <= gcm.NonceSize() {
		t.Fatalf("legacy blob length = %d", len(blob))
	}
	got, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], nil)
	if err != nil {
		t.Fatalf("v0.2.0-style decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted plaintext = %q, want fixture", got)
	}
}

func TestRollbackConfigOmitsPostV020Fields(t *testing.T) {
	document := configDocument(8080, "https://127.0.0.1:9443", "/tmp/store", "", 0, false)
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	kms := decoded["kms"].(map[string]any)
	local := kms["local"].(map[string]any)
	if _, exists := local["minimum_envelope_version"]; exists {
		t.Fatal("v0.2.0 rollback config contains minimum_envelope_version")
	}
	auth := decoded["auth"].(map[string]any)
	if _, exists := auth["revocation"]; exists {
		t.Fatal("v0.2.0 rollback config contains auth.revocation")
	}
}

func TestRestoreOwnerOnlyFileCopiesExactConfigAndRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "old.json")
	destination := filepath.Join(root, "restored.json")
	fixture := []byte(`{"server":{"address":"127.0.0.1:8080"}}`)
	if err := os.WriteFile(source, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	expectedDigest := fmt.Sprintf("%x", sha256.Sum256(fixture))
	if err := restoreOwnerOnlyFile(source, destination, expectedDigest); err != nil {
		t.Fatalf("restoreOwnerOnlyFile: %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fixture) || info.Mode().Perm() != 0o600 {
		t.Fatalf("restored config bytes=%q mode=%o", got, info.Mode().Perm())
	}
	link := filepath.Join(root, "old-link.json")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if err := restoreOwnerOnlyFile(link, filepath.Join(root, "should-not-exist.json"), expectedDigest); err == nil {
		t.Fatal("restoreOwnerOnlyFile accepted a symlink")
	}
}

func TestRestoreOwnerOnlyFileReadsOpenedInodeWhenPathIsReplacedByFIFO(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "old.json")
	destination := filepath.Join(root, "restored.json")
	fixture := []byte(`{"server":{"address":"127.0.0.1:8080"}}`)
	if err := os.WriteFile(source, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	expectedDigest := fmt.Sprintf("%x", sha256.Sum256(fixture))
	originalHook := afterSecureFileOpenHook
	var once sync.Once
	var hookErr error
	afterSecureFileOpenHook = func() {
		once.Do(func() {
			if err := os.Rename(source, source+".opened"); err != nil {
				hookErr = err
				return
			}
			if err := syscall.Mkfifo(source, 0o600); err != nil {
				hookErr = err
			}
		})
	}
	t.Cleanup(func() { afterSecureFileOpenHook = originalHook })

	done := make(chan error, 1)
	go func() { done <- restoreOwnerOnlyFile(source, destination, expectedDigest) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("restoreOwnerOnlyFile after path replacement: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("restoreOwnerOnlyFile blocked after source path became FIFO")
	}
	if hookErr != nil {
		t.Fatalf("replace opened source path: %v", hookErr)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fixture) {
		t.Fatalf("restored bytes = %q, want opened inode %q", got, fixture)
	}
}

func TestRestoreEncryptedBackupRequiresRecordedDigestsAndBoundsInputs(t *testing.T) {
	root := t.TempDir()
	backup := filepath.Join(root, "backup")
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "fixture.key"
	original := []byte("encrypted-original")
	if err := os.WriteFile(filepath.Join(backup, name), original, 0o600); err != nil {
		t.Fatal(err)
	}
	recorded := map[string]string{name: fmt.Sprintf("%x", sha256.Sum256(original))}
	if err := os.WriteFile(filepath.Join(backup, name), []byte("encrypted-replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "restored")
	if err := restoreEncryptedBackup(backup, destination, recorded); err == nil {
		t.Fatal("restoreEncryptedBackup accepted bytes that do not match the recorded snapshot")
	}
	if _, err := os.Stat(filepath.Join(destination, name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched backup produced destination entry: %v", err)
	}

	oversizedBackup := filepath.Join(root, "oversized-backup")
	if err := os.Mkdir(oversizedBackup, 0o700); err != nil {
		t.Fatal(err)
	}
	oversized := bytes.Repeat([]byte{'x'}, maxDrillFileBytes+1)
	if err := os.WriteFile(filepath.Join(oversizedBackup, name), oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	oversizedRecorded := map[string]string{name: fmt.Sprintf("%x", sha256.Sum256(oversized))}
	if err := restoreEncryptedBackup(oversizedBackup, filepath.Join(root, "oversized-restored"), oversizedRecorded); err == nil {
		t.Fatal("restoreEncryptedBackup accepted an oversized encrypted blob")
	}
}

func TestEncryptedBackupDirectoryRejectsSymlinkUnsafeModeAndEntryOverflow(t *testing.T) {
	root := t.TempDir()
	realBackup := filepath.Join(root, "real-backup")
	if err := os.Mkdir(realBackup, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realBackup, "fixture.key"), []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "backup-link")
	if err := os.Symlink(realBackup, link); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotEncryptedDirectory(link); err == nil {
		t.Fatal("snapshotEncryptedDirectory followed a directory symlink")
	}
	if err := os.Chmod(realBackup, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotEncryptedDirectory(realBackup); err == nil {
		t.Fatal("snapshotEncryptedDirectory accepted a non-owner-only directory")
	}

	overflow := filepath.Join(root, "overflow")
	if err := os.Mkdir(overflow, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index <= maxEncryptedBackupEntries; index++ {
		name := fmt.Sprintf("entry-%03d.key", index)
		if err := os.WriteFile(filepath.Join(overflow, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := snapshotEncryptedDirectory(overflow); err == nil {
		t.Fatal("snapshotEncryptedDirectory accepted too many entries")
	}
}

func TestRestoreEncryptedBackupUsesFixedDirectoryFDAndAggregateBound(t *testing.T) {
	root := t.TempDir()
	backup := filepath.Join(root, "backup")
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "fixture.key"
	original := []byte("encrypted-original")
	if err := os.WriteFile(filepath.Join(backup, name), original, 0o600); err != nil {
		t.Fatal(err)
	}
	recorded := map[string]string{name: fmt.Sprintf("%x", sha256.Sum256(original))}
	replacement := filepath.Join(root, "replacement")
	if err := os.Mkdir(replacement, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(replacement, name), []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalHook := afterSecureDirectoryOpenHook
	var once sync.Once
	var hookErr error
	afterSecureDirectoryOpenHook = func() {
		once.Do(func() {
			if err := os.Rename(backup, backup+".opened"); err != nil {
				hookErr = err
				return
			}
			if err := os.Symlink(replacement, backup); err != nil {
				hookErr = err
			}
		})
	}
	t.Cleanup(func() { afterSecureDirectoryOpenHook = originalHook })
	destination := filepath.Join(root, "restored")
	if err := restoreEncryptedBackup(backup, destination, recorded); err != nil {
		t.Fatalf("restoreEncryptedBackup with replaced path: %v", err)
	}
	if hookErr != nil {
		t.Fatalf("replace opened backup directory: %v", hookErr)
	}
	got, err := os.ReadFile(filepath.Join(destination, name))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("restored bytes = %q, want fixed-dirfd bytes %q", got, original)
	}

	aggregate := filepath.Join(root, "aggregate")
	if err := os.Mkdir(aggregate, 0o700); err != nil {
		t.Fatal(err)
	}
	remaining := maxEncryptedBackupAggregateBytes + 1
	for index := 0; remaining > 0; index++ {
		size := maxDrillFileBytes
		if remaining < size {
			size = remaining
		}
		name := fmt.Sprintf("aggregate-%03d.key", index)
		if err := os.WriteFile(filepath.Join(aggregate, name), bytes.Repeat([]byte{'x'}, size), 0o600); err != nil {
			t.Fatal(err)
		}
		remaining -= size
	}
	if _, err := snapshotEncryptedDirectory(aggregate); err == nil {
		t.Fatal("snapshotEncryptedDirectory accepted aggregate bytes above the bound")
	}
}

func TestReadSecretFileRejectsOversizedAndFIFOInputsWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	oversized := filepath.Join(root, "oversized.jwt")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte{'x'}, maxDrillFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(oversized); err == nil {
		t.Fatal("readSecretFile accepted oversized secret output")
	}

	fifo := filepath.Join(root, "token.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readSecretFile(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("readSecretFile accepted FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("readSecretFile blocked on FIFO")
	}
}

func initTestRepository(t *testing.T, dirty bool) string {
	t.Helper()
	repo := t.TempDir()
	runGit(t, repo, "init", "-q")
	runGit(t, repo, "config", "user.email", "rollback-drill@example.invalid")
	runGit(t, repo, "config", "user.name", "Rollback Drill Test")
	path := filepath.Join(repo, "tracked")
	if err := os.WriteFile(path, []byte("clean\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", "tracked")
	runGit(t, repo, "commit", "-q", "-m", "fixture")
	if dirty {
		if err := os.WriteFile(path, []byte("dirty\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return repo
}

func initEmptyTestRepository(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	runGit(t, repo, "init", "-q")
	runGit(t, repo, "config", "user.email", "rollback-drill@example.invalid")
	runGit(t, repo, "config", "user.name", "Rollback Drill Test")
	runGit(t, repo, "commit", "-q", "--allow-empty", "-m", "empty fixture")
	return repo
}

func runGit(t *testing.T, repo string, args ...string) {
	t.Helper()
	if _, err := gitOutput(repo, args...); err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
}

func gitOutputT(t *testing.T, repo string, args ...string) string {
	t.Helper()
	output, err := gitOutput(repo, args...)
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return output
}

func gitOutput(repo string, args ...string) (string, error) {
	gitArgs := append([]string{"-C", repo}, args...)
	cmd := exec.Command(trustedGitPath, gitArgs...) // #nosec G204 -- fixed absolute Git binary; arguments only construct isolated test fixtures.
	environment := append(identityEnvironment(),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_OPTIONAL_LOCKS=0",
	)
	stdout, _, err := runBoundedCommand(context.Background(), 15*time.Second, cmd, environment)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stdout), nil
}
