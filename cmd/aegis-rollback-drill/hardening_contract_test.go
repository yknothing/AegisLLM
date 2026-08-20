package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

const (
	testRollbackRunID            = "019ff59d-b35c-79c1-992c-2b51460e6255"
	testRollbackContainmentNonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testRollbackRunnerDigest     = "1111111111111111111111111111111111111111111111111111111111111111"
)

func TestRollbackInputLockV2BindsRunnerAndContainmentIdentity(t *testing.T) {
	lock, err := parseRollbackInputLock(validRollbackInputLockJSON())
	if err != nil {
		t.Fatalf("parseRollbackInputLock rejected the v2 runner/containment contract: %v", err)
	}

	// Decode independently so this RED contract does not compile against fields
	// that the implementation has not introduced yet.
	var raw map[string]string
	if err := json.Unmarshal(validRollbackInputLockJSON(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw["schema"] != "aegis.rollback-input-lock/v2" ||
		raw["run_id"] != testRollbackRunID ||
		raw["containment_nonce"] != testRollbackContainmentNonce ||
		raw["runner_binary_sha256"] != testRollbackRunnerDigest {
		t.Fatalf("v2 fixture lost an exact runner/containment binding: %+v", raw)
	}
	if lock.Schema != "aegis.rollback-input-lock/v2" {
		t.Fatalf("parsed schema = %q, want v2", lock.Schema)
	}
}

func TestRollbackInputLockV2RejectsMissingOrNoncanonicalRunnerAndContainmentBindings(t *testing.T) {
	valid := string(validRollbackInputLockJSON())
	variants := map[string]string{
		"missing run id": strings.Replace(valid,
			`  "run_id": "`+testRollbackRunID+`",`+"\n", "", 1),
		"uppercase run id": strings.Replace(valid, testRollbackRunID,
			strings.ToUpper(testRollbackRunID), 1),
		"nil run id": strings.Replace(valid, testRollbackRunID,
			"00000000-0000-0000-0000-000000000000", 1),
		"short containment nonce": strings.Replace(valid, testRollbackContainmentNonce,
			strings.Repeat("a", 62), 1),
		"uppercase containment nonce": strings.Replace(valid, testRollbackContainmentNonce,
			strings.ToUpper(testRollbackContainmentNonce), 1),
		"nil containment nonce": strings.Replace(valid, testRollbackContainmentNonce,
			strings.Repeat("0", 64), 1),
		"missing runner digest": strings.Replace(valid,
			`  "runner_binary_sha256": "`+testRollbackRunnerDigest+`",`+"\n", "", 1),
		"short runner digest": strings.Replace(valid, testRollbackRunnerDigest,
			strings.Repeat("1", 62), 1),
		"unsafe runner provenance": strings.Replace(valid,
			"https://evidence.example/rollback-runner.intoto.jsonl",
			"file:///tmp/caller-selected-runner.intoto.jsonl", 1),
		"fragmented runner provenance": strings.Replace(valid,
			"https://evidence.example/rollback-runner.intoto.jsonl",
			"https://evidence.example/rollback-runner.intoto.jsonl#mutable", 1),
		"short runner provenance digest": strings.Replace(valid,
			strings.Repeat("2", 64), strings.Repeat("2", 62), 1),
	}
	for name, document := range variants {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRollbackInputLock([]byte(document)); err == nil {
				t.Fatalf("parseRollbackInputLock accepted %s", name)
			}
		})
	}
}

func TestRollbackSuccessSummaryIsExactSpliceResistantJSON(t *testing.T) {
	want := `{"schema_version":3,"result":"PASS","evidence_class":"FINAL_CANDIDATE","worktree_clean":true,"run_id":"019ff59d-b35c-79c1-992c-2b51460e6255","containment_nonce":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","started_at":"2026-08-20T00:00:00Z","ended_at":"2026-08-20T00:10:00Z","runner_binary_sha256":"1111111111111111111111111111111111111111111111111111111111111111","candidate_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","rollback_source_sha":"aece3298720d210f5dd242aebd72ac71af4b2aff","candidate_binary_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rollback_binary_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","input_lock_digest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","migration":"legacy_file_store_to_v2_strict_pass","current_smoke":"health_auth_kms_tls_provider_200_pass","rollback":"encrypted_backup_restore_v0.2.0_health_auth_kms_tls_provider_200_pass"}`

	var summary successSummary
	if err := json.Unmarshal([]byte(want), &summary); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := writeSummary(&output, summary); err != nil {
		t.Fatalf("writeSummary: %v", err)
	}
	if got := output.String(); got != want+"\n" {
		t.Fatalf("summary is not the exact canonical evidence line:\n got: %s\nwant: %s", got, want+"\n")
	}
}

func TestRollbackSuccessSummaryRejectsMissingIdentityAndNoncanonicalTimes(t *testing.T) {
	valid := `{"schema_version":3,"result":"PASS","evidence_class":"FINAL_CANDIDATE","worktree_clean":true,"run_id":"019ff59d-b35c-79c1-992c-2b51460e6255","containment_nonce":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","started_at":"2026-08-20T00:00:00Z","ended_at":"2026-08-20T00:10:00Z","runner_binary_sha256":"1111111111111111111111111111111111111111111111111111111111111111","candidate_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","rollback_source_sha":"aece3298720d210f5dd242aebd72ac71af4b2aff","candidate_binary_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rollback_binary_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","input_lock_digest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","migration":"legacy_file_store_to_v2_strict_pass","current_smoke":"health_auth_kms_tls_provider_200_pass","rollback":"encrypted_backup_restore_v0.2.0_health_auth_kms_tls_provider_200_pass"}`
	variants := map[string]string{
		"missing run id":            strings.Replace(valid, `"run_id":"`+testRollbackRunID+`",`, "", 1),
		"missing containment nonce": strings.Replace(valid, `"containment_nonce":"`+testRollbackContainmentNonce+`",`, "", 1),
		"missing runner digest":     strings.Replace(valid, `"runner_binary_sha256":"`+testRollbackRunnerDigest+`",`, "", 1),
		"non-UTC start":             strings.Replace(valid, "2026-08-20T00:00:00Z", "2026-08-20T08:00:00+08:00", 1),
		"end before start":          strings.Replace(valid, "2026-08-20T00:10:00Z", "2026-08-19T23:59:59Z", 1),
	}
	for name, document := range variants {
		t.Run(name, func(t *testing.T) {
			var summary successSummary
			if err := json.Unmarshal([]byte(document), &summary); err != nil {
				t.Fatal(err)
			}
			if err := writeSummary(&bytes.Buffer{}, summary); err == nil {
				t.Fatalf("writeSummary accepted %s", name)
			}
		})
	}
}

func TestRollbackRunnerSourceOwnsSignalsGatewaysAndItsExactExecutableIdentity(t *testing.T) {
	root := rollbackRepositoryRoot(t)
	mainPath := filepath.Join(root, "cmd", "aegis-rollback-drill", "main.go")
	mainSource := readContractFile(t, mainPath)

	for _, required := range []string{
		`"os/signal"`,
		`signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)`,
		`"/proc/self/exe"`,
		`lock.RunnerBinarySHA256`,
		`RunnerBinarySHA256:`,
		`RunID:`,
		`inputLock.RunID`,
		`ContainmentNonce:`,
		`inputLock.ContainmentNonce`,
		`StartedAt:`,
		`EndedAt:`,
	} {
		if !strings.Contains(mainSource, required) {
			t.Errorf("rollback runner source is missing required contract %q", required)
		}
	}
	if strings.Contains(mainSource, "run(context.Background(), opts, os.Stdout)") {
		t.Error("main invokes the drill with an uncancellable background context")
	}

	assertGatewayStartsAreImmediatelyOwned(t, mainPath)

	linuxAttrs := readContractFile(t, filepath.Join(root, "cmd", "aegis-rollback-drill", "process_attr_linux.go"))
	for _, required := range []string{"//go:build linux", "Setpgid:", "Pdeathsig:", "syscall.SIGKILL"} {
		if !strings.Contains(linuxAttrs, required) {
			t.Errorf("Linux child attributes are missing %q", required)
		}
	}
	darwinAttrs := readContractFile(t, filepath.Join(root, "cmd", "aegis-rollback-drill", "process_attr_darwin.go"))
	for _, required := range []string{"//go:build darwin", "Setpgid:", "true"} {
		if !strings.Contains(darwinAttrs, required) {
			t.Errorf("Darwin child attributes are missing %q", required)
		}
	}
	if count := strings.Count(mainSource, "childProcessAttributes()"); count < 2 {
		t.Errorf("child process helper uses = %d, want at least bounded commands and gateways", count)
	}
}

func TestValidateRollbackRunnerBuildInfoBindsPackageRevisionAndDirtyState(t *testing.T) {
	sha := strings.Repeat("a", 40)
	valid := func() *debug.BuildInfo {
		return &debug.BuildInfo{
			Path: aegisRollbackRunnerPackagePath,
			Main: debug.Module{Path: aegisModulePath},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: sha},
				{Key: "vcs.modified", Value: "false"},
			},
		}
	}
	for name, mutate := range map[string]func(*debug.BuildInfo){
		"wrong package":  func(info *debug.BuildInfo) { info.Path = aegisMainPackagePath },
		"wrong module":   func(info *debug.BuildInfo) { info.Main.Path = "example.invalid/AegisLLM" },
		"wrong revision": func(info *debug.BuildInfo) { info.Settings[0].Value = strings.Repeat("b", 40) },
		"dirty mismatch": func(info *debug.BuildInfo) { info.Settings[1].Value = "true" },
		"duplicate revision": func(info *debug.BuildInfo) {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: "vcs.revision", Value: sha})
		},
	} {
		t.Run(name, func(t *testing.T) {
			info := valid()
			mutate(info)
			if err := validateRollbackRunnerBuildInfo(info, sha, false); err == nil {
				t.Fatalf("validateRollbackRunnerBuildInfo accepted %s", name)
			}
		})
	}
	if err := validateRollbackRunnerBuildInfo(valid(), sha, false); err != nil {
		t.Fatalf("validateRollbackRunnerBuildInfo rejected exact identity: %v", err)
	}
}

func TestRollbackMakeTargetAndRunbookRequireCallerSuppliedPrebuiltRunner(t *testing.T) {
	root := rollbackRepositoryRoot(t)
	makefile := readContractFile(t, filepath.Join(root, "Makefile"))
	start := strings.Index(makefile, "rollback-drill:")
	if start < 0 {
		t.Fatal("could not locate rollback-drill Make target")
	}
	end := strings.Index(makefile[start:], "\nrelease-manifest-schema:")
	if end < 0 {
		t.Fatal("could not isolate rollback-drill Make target")
	}
	target := makefile[start : start+end]
	for _, required := range []string{
		`@test -n "$(RUNNER_BIN)"`,
		`@test -x "$(RUNNER_BIN)"`,
		`"$(RUNNER_BIN)"`,
		`@test -n "$(INPUT_LOCK)"`,
		`@test -n "$(INPUT_LOCK_SHA256)"`,
	} {
		if !strings.Contains(target, required) {
			t.Errorf("rollback-drill target is missing %q", required)
		}
	}
	if strings.Contains(target, "$(GO) run") || strings.Contains(target, "go run") {
		t.Error("rollback-drill target still executes an ambient source-built runner")
	}

	runbook := strings.Join(strings.Fields(readContractFile(t, filepath.Join(root, "docs", "release-plan-v0.2.1.md"))), " ")
	for _, required := range []string{
		"RUNNER_BIN=/absolute/path/to/verified/aegis-rollback-drill",
		"aegis.rollback-input-lock/v2",
		"runner binary digest",
		"runner provenance reference and digest",
		"run ID and containment nonce",
		"started_at",
		"ended_at",
		"does not validate the lock's authority",
		"external containment",
	} {
		if !strings.Contains(runbook, required) {
			t.Errorf("rollback runbook is missing %q", required)
		}
	}
}

func rollbackRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate rollback contract test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourcePath), "..", ".."))
}

func readContractFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read contract file %s: %v", path, err)
	}
	return string(data)
}

func assertGatewayStartsAreImmediatelyOwned(t *testing.T, path string) {
	t.Helper()
	set := token.NewFileSet()
	parsed, err := parser.ParseFile(set, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var runBody *ast.BlockStmt
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "run" {
			runBody = function.Body
			break
		}
	}
	if runBody == nil {
		t.Fatal("run function is missing")
	}

	starts := 0
	for index, statement := range runBody.List {
		assignment, ok := statement.(*ast.AssignStmt)
		if !ok || len(assignment.Rhs) == 0 {
			continue
		}
		call, ok := assignment.Rhs[0].(*ast.CallExpr)
		if !ok {
			continue
		}
		identifier, ok := call.Fun.(*ast.Ident)
		if !ok || identifier.Name != "startGateway" {
			continue
		}
		starts++
		if len(assignment.Lhs) == 0 {
			t.Fatalf("startGateway assignment has no process owner")
		}
		owner, ok := assignment.Lhs[0].(*ast.Ident)
		if !ok {
			t.Fatalf("startGateway owner is not a stable identifier: %s", contractNodeText(t, set, assignment.Lhs[0]))
		}
		owned := false
		for following := index + 1; following < len(runBody.List) && following <= index+2; following++ {
			deferStatement, ok := runBody.List[following].(*ast.DeferStmt)
			if !ok {
				continue
			}
			deferText := contractNodeText(t, set, deferStatement)
			if strings.Contains(deferText, owner.Name+".stop()") {
				owned = true
				break
			}
		}
		if !owned {
			t.Errorf("%s is not owned by a cleanup defer immediately after its successful start", owner.Name)
		}
	}
	if starts != 2 {
		t.Errorf("startGateway calls = %d, want exact candidate and rollback gateways", starts)
	}
}

func contractNodeText(t *testing.T, set *token.FileSet, node ast.Node) string {
	t.Helper()
	var output bytes.Buffer
	if err := format.Node(&output, set, node); err != nil {
		t.Fatalf("format AST node: %v", err)
	}
	return output.String()
}

func TestRollbackContractFixtureHasUniqueDigestRoles(t *testing.T) {
	var raw map[string]string
	if err := json.Unmarshal(validRollbackInputLockJSON(), &raw); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]string)
	for _, field := range []string{
		"candidate_binary_sha256",
		"candidate_provenance_sha256",
		"rollback_binary_sha256",
		"rollback_provenance_sha256",
		"runner_binary_sha256",
		"runner_provenance_sha256",
		"trust_policy_sha256",
	} {
		value := raw[field]
		if previous, exists := seen[value]; exists {
			t.Fatalf("fixture fields %s and %s accidentally share digest %s", previous, field, value)
		}
		seen[value] = field
	}
	if len(seen) != 7 {
		t.Fatalf("digest role count = %d, want 7", len(seen))
	}
}
