# Independent QA Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and govern a separate binary-only AegisLLM QA repository, pin it into source CI, and produce source-SHA/QA-SHA/artifact-digest-bound acceptance evidence.

**Architecture:** `AegisLLM-QA` is a standard-library-only Go module that never imports or reads Aegis source. It executes one exact prebuilt Linux binary through CLI, filesystem, HTTP, and a hermetic TLS fake provider. The source repository builds once, checks out a pinned QA commit that is an ancestor of protected QA `main`, runs it, and uploads a sanitized evidence report. macOS runs framework unit tests; its system roots cannot be redirected with the per-run `SSL_CERT_FILE` used by the initial Linux black-box lane.

**Tech Stack:** Go 1.22-compatible standard library, Go 1.26.5 release toolchain, pinned GitHub Actions, GitHub CODEOWNERS/rulesets, JSON evidence.

---

## File Map

Independent repository `yknothing/AegisLLM-QA`:

- `go.mod`: standalone module with no dependency on Aegis.
- `cmd/aegis-qa/main.go`: flags, suite execution, exit status.
- `internal/evidence/report.go`: evidence schema, binding validation, exclusive sanitized write.
- `internal/harness/process.go`: bounded subprocess execution and gateway lifecycle.
- `internal/harness/provider.go`: TLS 1.3 fake provider with synchronized in-memory captures.
- `internal/harness/workspace.go`: synthetic canaries, config, certificate, and state workspace.
- `internal/suite/suite.go`: required-case fail-closed runner.
- `internal/suite/baseline.go`: artifact, operator, HTTP, revocation, fail-closed, and confidentiality cases.
- `Dockerfile.runner`: scratch test image containing only the already-built QA runner and SUT.
- `.github/workflows/ci.yml`, `.github/CODEOWNERS`, `README.md`, `BASELINE.md`, `GOVERNANCE.md`.

Source repository `yknothing/AegisLLM`:

- `qa-baseline.lock`: canonical QA repository and immutable commit.
- `.github/workflows/independent-qa.yml`: single-build, pinned-checkout black-box gate.
- `.github/CODEOWNERS`: protected QA integration surfaces.
- `docs/independent-qa.md`: operator and governance runbook.
- `scripts/release_preflight.sh`: validate every workflow.

## Task 1: Bootstrap the Independent QA Repository

**Files:** Create `go.mod` in a clean `/tmp/AegisLLM-QA` repository.

- [ ] Initialize `main`, then add:

```go
module github.com/yknothing/AegisLLM-QA

go 1.22.4
```

- [ ] Run `go list -m all`; require exactly the QA module and no `require` or `replace` entry.
- [ ] Commit as `chore: bootstrap independent QA module`.

## Task 2: Build Bound Evidence with TDD

**Files:** Create `internal/evidence/report_test.go`, then `internal/evidence/report.go`.

- [ ] Write RED tests requiring source and QA Git object IDs to be exactly 40 lowercase hex and artifact SHA-256 to be exactly 64 lowercase hex; also cover missing/malformed bindings, digest mismatch, duplicate cases, required non-pass cases, forbidden canaries in serialized JSON, exclusive create, and `0600` mode.
- [ ] Run `go test ./internal/evidence -count=1`; require compile failure before implementation.
- [ ] Implement these contracts:

```go
type Binding struct {
    SourceSHA string `json:"source_sha"`
    HeadSHA string `json:"head_sha,omitempty"`
    BaseSHA string `json:"base_sha,omitempty"`
    QASHA string `json:"qa_sha"`
    ArtifactSHA256 string `json:"artifact_sha256"`
    WorkflowRunID string `json:"workflow_run_id,omitempty"`
}
type CaseResult struct {
    Name string `json:"name"`
    Status string `json:"status"`
    DurationMS int64 `json:"duration_ms"`
    Detail string `json:"detail,omitempty"`
}
type Report struct {
    SchemaVersion int `json:"schema_version"`
    Binding Binding `json:"binding"`
    StartedAt time.Time `json:"started_at"`
    CompletedAt time.Time `json:"completed_at"`
    GoVersion string `json:"go_version"`
    OS string `json:"os"`
    Arch string `json:"arch"`
    Status string `json:"status"`
    Cases []CaseResult `json:"cases"`
    Gaps []string `json:"gaps"`
}
func (b Binding) Validate() error
func (r Report) Validate(requiredCases, forbiddenCanaries []string) error
func WriteAtomicExclusive(path string, r Report, requiredCases, forbiddenCanaries []string) error
func SHA256File(path string) (string, error)
```

`WriteAtomicExclusive` validates and serializes to memory, writes and syncs an owner-only temporary file, atomically links it to an absent final path, then removes the temporary name. Errors identify fields, never secret values.

- [ ] Run `go test -race -count=1 ./internal/evidence`; require `ok`.
- [ ] Commit as `feat: bind QA evidence to immutable revisions`.

## Task 3: Build the Bounded Process Harness with TDD

**Files:** Create `internal/harness/process_test.go`, then `internal/harness/process.go`.

- [ ] Write RED tests using Go's helper-process pattern, not `/bin/sh`, for stdin, a minimal explicit environment, non-zero exit, context timeout, separate bounded stdout/stderr, health deadline, graceful interrupt, process-group forced kill, and cleanup.
- [ ] Implement:

```go
type CommandResult struct {
    ExitCode int
    Stdout string
    Stderr string
    Truncated bool
    Duration time.Duration
}
func Run(ctx context.Context, binary string, args []string, stdin []byte, env map[string]string, maxOutput int) (CommandResult, error)
type Gateway struct { /* private process state */ }
func StartGateway(ctx context.Context, binary, configPath string, env map[string]string, logLimit int) (*Gateway, error)
func (g *Gateway) WaitHealthy(ctx context.Context, url string) error
func (g *Gateway) Stop(ctx context.Context) error
func (g *Gateway) Logs() (stdout, stderr string, truncated bool)
```

Use synchronized concurrently drained bounded writers; never use unbounded `CombinedOutput`. Output overflow is a hard failure, not a truncated success. Construct child environments from explicit `PATH`, `HOME`, and `TMPDIR` plus synthetic `AEGIS_*` and CA values; remove inherited `AEGIS_*`, proxy, and real-config variables. Provider keys enter only through stdin. `Stop` signals the process group, waits exactly once to deadline, then kills the group.

- [ ] Run `go test -race -shuffle=on -count=10 ./internal/harness -run 'TestRun|TestGateway'`.
- [ ] Commit as `feat: add bounded binary process harness`.

## Task 4: Build the Hermetic TLS Provider and Workspace with TDD

**Files:** Create `internal/harness/provider_test.go`, `provider.go`, `workspace_test.go`, `workspace.go`.

- [ ] Write RED tests for TLS 1.3, JSON `200`, response-header filtering canary, synchronized hit count, defensive capture copies, random canaries, owner-only paths, and strict config generation.
- [ ] Implement:

```go
type ProviderCapture struct {
    Method, Path, Authorization, ClientAPIKey string
    Body []byte
    TLSVersion uint16
}
type Provider struct { /* private httptest server and mutex */ }
func StartProvider(completionCanary string) (*Provider, error)
func (p *Provider) URL() string
func (p *Provider) RootCAFile() string
func (p *Provider) HitCount() int
func (p *Provider) Captures() []ProviderCapture
func (p *Provider) Close()

type Workspace struct {
    Root, ConfigPath, KeyDir, RevocationPath, TokenPath, GatewayURL string
    MasterKey, JWTKey, ProviderKey, VirtualKey, Prompt, Completion, Error string
}
func NewWorkspace(providerURL, providerCAFile string) (*Workspace, error)
func (w *Workspace) Environment() map[string]string
func (w *Workspace) Close() error
```

The generated config uses one OpenAI-compatible provider, loopback egress only, file KMS/revocation, bounded timeouts, and an ephemeral gateway port. In the Linux black-box lane, set `SSL_CERT_FILE` for the unmodified Aegis child so its system root pool trusts the synthetic provider CA. Use `encoding/json`, never template substitution. macOS unit tests must not claim black-box provider success.

- [ ] Run `go test -race -shuffle=on -count=10 ./internal/harness -run 'TestProvider|TestWorkspace'`.
- [ ] Commit as `feat: add hermetic TLS provider workspace`.

## Task 5: Build a Fail-Closed Suite Runner with TDD

**Files:** Create `internal/suite/suite_test.go`, then `internal/suite/suite.go`.

- [ ] Write RED tests proving duplicate names, nil functions, and panics fail the report; every required case runs; no `skip` exists; overall pass requires all required cases.
- [ ] Implement:

```go
type Context struct { Binary, SourceSHA, QASHA, ArtifactSHA256 string }
type Case struct { Name string; Required bool; Run func(context.Context, *Context) error }
func Run(ctx context.Context, runContext *Context, cases []Case) evidence.Report
```

Panic details must be classified without persisting the raw panic value.

- [ ] Run `go test -race -count=1 ./internal/suite -run TestRun`.
- [ ] Commit as `feat: make required QA cases fail closed`.

## Task 6: Implement the Binary-Only Baseline

**Files:** Create `internal/suite/baseline_test.go`, then `internal/suite/baseline.go`.

- [ ] RED-test that `Baseline()` registers these unique required cases:

```text
artifact_identity
network_namespace_isolation
operator_lifecycle
http_unauthenticated_no_egress
http_authenticated_provider_success
http_revoked_no_egress
http_route_and_header_contract
unsupported_capabilities_fail_closed
secret_canary_confinement
```

- [ ] Give every registered case a fresh fixture and independent cleanup. `network_namespace_isolation` requires Linux, requires `lo`, and rejects every non-loopback/default route in `/proc/net/route`; unrouted kernel interfaces may remain visible on Docker Desktop. `operator_lifecycle` performs init/import/issue as one coherent journey; authenticated and revoked HTTP cases each perform their own setup. Do not use package globals or rely on case order.
- [ ] Execute the real binary to verify: pre-run digest; Go build info `vcs.revision`/`vcs.modified=false`/toolchain; exact version; `0600` revocation state; provider-key import via stdin without echo; exclusive `0600` token issue; health; unauthenticated `401` with provider hit delta zero; authenticated TLS provider `200`; PII redaction; correct provider credential and no client credential upstream; revocation propagation; unsupported routes/config fail closed; post-run digest unchanged; gateway logs, state, error bodies, and report projection obey per-surface canary allowlists.
- [ ] Poll revocation with an authenticated but syntactically invalid body: accept `400` before refresh and require `401` after refresh, so polling can never reach the provider. After observing `401`, send one valid body and require `401` plus an unchanged provider hit count.
- [ ] Keep expected provider-key/prompt/completion/error appearances only in explicitly scoped captures. Permit the virtual key only in its owner-only token file and client input. Every defer path, including failure and panic, scans logs/state before deletion; CLI output contains classifications only. Then delete the workspace and never copy a raw canary to evidence.
- [ ] Prove the oracle goes RED with a test helper that incorrectly returns unauthenticated `200`.
- [ ] Run `go test -race -shuffle=on -count=3 ./...` without Aegis source present.
- [ ] Commit as `test: define independent Aegis security baseline`.

## Task 7: Add the QA CLI and Run the Exact Artifact

**Files:** Create `cmd/aegis-qa/main_test.go`, then `cmd/aegis-qa/main.go`.

- [ ] RED-test subcommands `run` and `verify`. `run` requires `--sut`, `--source-sha`, `--qa-sha`, `--artifact-sha256`, `--evidence`, and `--timeout`. `verify` requires the evidence plus independently supplied expected source/head/base/QA/artifact/workflow values and the SUT path. Missing/invalid inputs exit `2`, failed suite or verification exits `1`, pass exits `0`.
- [ ] Reject relative/missing binaries, digest mismatch, invalid timeout, an existing report, or a QA SHA inconsistent with the runner's build info/embedded `main.qaCommit` before cases run. `verify` rehashes the SUT and compares external expectations rather than trusting equality inside JSON.
- [ ] Run `go test -race -count=1 ./cmd/aegis-qa` after implementation.
- [ ] Build Aegis once on Linux with VCS metadata and the full source SHA embedded; build the QA runner from the checked-out QA commit with `-X main.qaCommit=$QA_SHA`; run `aegis-qa run`, then `aegis-qa verify` with independent expectations. Require all cases pass, pre/post hashes match, build info is clean, and the evidence file contains no raw canary.
- [ ] Commit as `feat: add independent QA baseline runner`.

## Task 8: Add QA Governance, Documentation, and CI

**Files:** Create `.github/workflows/ci.yml`, `.github/CODEOWNERS`, `Dockerfile.runner`, `README.md`, `BASELINE.md`, `GOVERNANCE.md`, `testdata/README.md`.

- [ ] Pin checkout/setup-go actions. Run Go 1.22.4 compatibility plus Go 1.26.5 race/shuffle. Use `permissions: contents: read`, no secrets, and assert `go list -m all` contains only the QA module.
- [ ] `Dockerfile.runner` uses `FROM scratch` and only `COPY --chmod=0555` for prebuilt `aegis-qa` and `aegis`; it has no build stage and therefore cannot rebuild the SUT.
- [ ] Document separate source/QA PRs, immutable binding tuple, synthetic-only data, P0 no-waiver, seven-day P1/P2 waiver, stale/latest-push review, no routine bypass, and evidence retention.
- [ ] Bootstrap CODEOWNERS with `@yknothing` but explicitly mark this as repository administration, not independent-human completion. Future baseline changes remain blocked until a real QA reviewer is granted write access and added as owner.
- [ ] Run `go test -race -shuffle=on -count=3 ./...`, `go vet ./...`, `gofmt -l .`, and `git diff --check`.
- [ ] Commit as `docs: govern the independent QA baseline`.

## Task 9: Publish and Freeze the QA Baseline

**External state:** Create public `yknothing/AegisLLM-QA` after local verification.

- [ ] Run `gh repo create yknothing/AegisLLM-QA --public --source /tmp/AegisLLM-QA --remote origin --push`.
- [ ] Verify remote `main` equals local HEAD and repository visibility is public.
- [ ] Export prior protection state to `/tmp`, then install an active no-bypass main ruleset: PR required, one approval, stale dismissal, latest-push approval, no force-push/delete.
- [ ] Read the ruleset/protection back through GitHub API. Record GitHub plan limitations exactly.

## Task 10: Integrate the Pinned QA Baseline into Aegis

**Files:** Create `qa-baseline.lock`, `.github/workflows/independent-qa.yml`, `.github/CODEOWNERS`, `docs/independent-qa.md`; modify `scripts/release_preflight.sh`.

- [ ] Write a placeholder-free JSON lock containing schema `1`, repository `yknothing/AegisLLM-QA`, and the exact published 40-hex QA SHA.
- [ ] Add workflow job `Independent QA baseline`: source checkout with `persist-credentials:false`; set tested SHA from `git rev-parse HEAD` and separately record PR head/base SHAs; Go 1.26.5; build Aegis once with full tested SHA and VCS metadata; compute digest; strictly parse a fixed repository/schema and 40-lowercase-hex lock; checkout exact QA commit into a separate workspace with `persist-credentials:false`; verify checkout SHA and that it is an ancestor of fetched QA `origin/main`; run QA unit tests; build the QA runner with its QA SHA embedded; create the scratch runner image without rebuilding SUT; run it as the host UID with `--network none --read-only`, a `noexec,nosuid` tmpfs, and a single evidence bind mount; rehash the host SUT, then run `verify` against external expectations.
- [ ] Upload with `if: always()` only the exact `report-v1.json`, `if-no-files-found: error`, and 30-day retention. Record the returned artifact digest/run ID when available; never upload raw logs or captures.
- [ ] Add `QA baseline change isolation`: after bootstrap, a PR changing `qa-baseline.lock` must change only that file. The bootstrap case may allow only the exact initial governance/workflow/design file set and ceases to apply once the base contains the lock.
- [ ] Give workflow `contents: read` only. Pin action SHAs. Never use `pull_request_target`, real provider secrets, or an unpinned QA branch.
- [ ] Add CODEOWNERS for the lock, workflow, ownership file, runbook, design, and plan. Document that real QA identities must replace/join the bootstrap owner before independent-human completion.
- [ ] Update release preflight to actionlint every existing `.yml`/`.yaml` workflow with POSIX-safe file discovery.
- [ ] Run source unit, race, vet, actionlint, and `git diff --check`.
- [ ] Commit as `ci: require the independent QA baseline`.

## Task 11: Install Source Governance

**External state:** Protect Aegis `main`.

- [ ] Export current rulesets/protection/collaborators to `/tmp`.
- [ ] Require PR, one approval, code-owner review, stale dismissal, latest-push approval, conversation resolution, linear history, no force-push/delete, no routine bypass.
- [ ] Require `Go 1.22 compatibility`, `Quality gates`, `Docker smoke`, and `Independent QA baseline`. If the new context has not appeared, push the feature branch and let it report before retrying; do not weaken the rule.
- [ ] Read back API state and verify every condition. Any personal-account plan limitation remains an explicit failed/unverified criterion.

## Task 12: Adversarial Review and Final Acceptance

- [ ] QA repo fresh gate: `GOTOOLCHAIN=go1.26.5 go test -race -shuffle=on -count=10 ./...`, `go vet`, formatting, diff check.
- [ ] Source fresh gate: unit, race, vet, gosec, diff check, source/binary govulncheck. A vuln DB outage is `not_run`; use the established local DB fallback with recorded snapshot/hash when needed.
- [ ] Rebuild Aegis once in the Linux acceptance environment and create fresh final evidence; independently recompute tested/head/base source SHAs, QA SHA, pre/post artifact digest, build info, and workflow/run identity.
- [ ] Software engineer reviews correctness, cleanup, portability, resource bounds, and source isolation.
- [ ] Security QA tries to bypass the pin, forge bindings, inject canaries into output boundaries, omit a required case, and mutate unauth/no-egress behavior; fix findings and rerun all relevant gates.
- [ ] Verify used Skill frontmatter, description length, referenced files, and runtime loadability; do not mutate Skill canaries.
- [ ] Final handoff separately reports framework status, GitHub protection, actual QA identities, unimplemented performance/fuzz/mutation/platform lanes, and known revocation rollback limits.
