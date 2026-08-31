// Command aegis-rollback-drill executes the v0.2.1 local-KMS migration and
// v0.2.0 rollback contract against caller-supplied, prebuilt binaries.
//
// SECURITY PROPERTIES:
//   - It creates all credentials, encrypted stores, certificates, and configs
//     in one owner-only temporary directory and removes it; bounded child output
//     stays in memory and is never copied into evidence.
//   - It emits only hashes and fixed result codes; tokens, keys, request bodies,
//     child-process output, and temporary paths are never evidence fields.
//   - It copies each input into an immutable Linux memfd, binds version,
//     buildinfo, every execution, and final hashing to that one sealed fd, and
//     never downloads, builds, publishes, or modifies either input binary.
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- Git SHA-1 object identity compatibility only; never used as a security signature.
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/yknothing/AegisLLM/internal/utils"
)

const (
	evidenceFinal                          = "FINAL_CANDIDATE"
	evidenceIterationOnly                  = "ITERATION_ONLY"
	aegisModulePath                        = "github.com/yknothing/AegisLLM"
	aegisMainPackagePath                   = "github.com/yknothing/AegisLLM/cmd/aegis"
	aegisRollbackRunnerPackagePath         = "github.com/yknothing/AegisLLM/cmd/aegis-rollback-drill"
	rollbackRunnerExecutablePath           = "/proc/self/exe"
	trustedGitPath                         = "/usr/bin/git"
	rollbackV020SHA                        = "aece3298720d210f5dd242aebd72ac71af4b2aff"
	drillProviderKeyID                     = "rollback-drill-provider-key"
	drillProviderID                        = "rollback-drill-provider"
	drillModel                             = "rollback-drill-model"
	drillMasterKeyEnv                      = "AEGIS_ROLLBACK_DRILL_MASTER_KEY"
	drillJWTKeyEnv                         = "AEGIS_ROLLBACK_DRILL_JWT_KEY"
	maxChildOutputBytes                    = 64 << 10
	maxCandidateTreeOutputBytes            = 8 << 20
	maxCandidateTreeEntries                = 16 << 10
	maxCandidateWorktreeEntries            = 64 << 10
	maxCandidatePathBytes                  = 4 << 10
	maxCandidateWorktreePathBytes          = 16 << 20
	maxCandidateTreeDepth                  = 64
	maxCandidateSymlinkBytes               = 4 << 10
	maxCandidateBlobBytes            int64 = 64 << 20
	maxCandidateAggregateBytes       int64 = 512 << 20
	maxInputBinaryBytes                    = 512 << 20
	maxDrillFileBytes                      = 1 << 20
	maxEncryptedBackupEntries              = 128
	maxEncryptedBackupAggregateBytes       = 8 << 20
)

var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
var fullSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var canonicalRunID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var encryptedKeyFilename = regexp.MustCompile(`^[A-Za-z0-9_-]+\.key$`)
var hostGOOS = runtime.GOOS
var afterBinarySnapshotHook = func() {}
var afterSecureFileOpenHook = func() {}
var afterSecureDirectoryOpenHook = func() {}

type binarySnapshot struct {
	Candidate       *sealedExecutable
	Rollback        *sealedExecutable
	CandidateDigest string
	RollbackDigest  string
}

func (s *binarySnapshot) close() {
	if s == nil {
		return
	}
	if s.Candidate != nil {
		_ = s.Candidate.close()
	}
	if s.Rollback != nil {
		_ = s.Rollback.close()
	}
}

type sealedExecutable struct {
	file *os.File
	size int64
}

func (s *sealedExecutable) close() error {
	if s == nil || s.file == nil {
		return nil
	}
	return s.file.Close()
}

func (s *sealedExecutable) digest() (string, error) {
	if s == nil || s.file == nil || s.size < 1 || s.size > maxInputBinaryBytes {
		return "", errors.New("invalid sealed executable")
	}
	info, err := s.file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != s.size {
		return "", errors.New("sealed executable metadata changed")
	}
	if err := verifyExecutableSeals(s.file); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(s.file, 0, s.size)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type options struct {
	CandidateBinary     string
	RollbackBinary      string
	InputLock           string
	InputLockSHA256     string
	RepoRoot            string
	AllowDirtyIteration bool
}

type candidateIdentity struct {
	Dirty          bool
	EvidenceClass  string
	WorktreeDigest string
}

type candidateTreeEntry struct {
	Path     string
	Mode     string
	ObjectID string
	Size     int64
}

type candidateRepository struct {
	path     string
	worktree *os.File
	gitDir   *os.File
}

type candidateWorktreeEntry struct {
	Path          string
	Mode          string
	ObjectID      string
	ContentDigest string
	Size          int64
	RawMode       uint32
}

type candidateWorktreeSnapshot struct {
	Entries          map[string]candidateWorktreeEntry
	EntryCount       int
	AggregateBytes   int64
	AggregatePathLen int
}

type runnerSnapshot struct {
	file   *os.File
	size   int64
	digest string
}

func (s *runnerSnapshot) close() error {
	if s == nil || s.file == nil {
		return nil
	}
	return s.file.Close()
}

func (s *runnerSnapshot) currentDigest() (string, error) {
	if s == nil || s.file == nil || s.size < 1 || s.size > maxInputBinaryBytes {
		return "", errors.New("invalid runner executable snapshot")
	}
	info, err := s.file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != s.size {
		return "", errors.New("runner executable metadata changed")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(s.file, 0, s.size)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type successSummary struct {
	SchemaVersion         int    `json:"schema_version"`
	Result                string `json:"result"`
	EvidenceClass         string `json:"evidence_class"`
	WorktreeClean         bool   `json:"worktree_clean"`
	RunID                 string `json:"run_id"`
	ContainmentNonce      string `json:"containment_nonce"`
	StartedAt             string `json:"started_at"`
	EndedAt               string `json:"ended_at"`
	RunnerBinarySHA256    string `json:"runner_binary_sha256"`
	CandidateSHA          string `json:"candidate_sha"`
	RollbackSourceSHA     string `json:"rollback_source_sha"`
	CandidateBinarySHA256 string `json:"candidate_binary_sha256"`
	RollbackBinarySHA256  string `json:"rollback_binary_sha256"`
	InputLockDigest       string `json:"input_lock_digest"`
	Migration             string `json:"migration"`
	CurrentSmoke          string `json:"current_smoke"`
	Rollback              string `json:"rollback"`
}

type stageError struct {
	Stage  string
	Reason string
}

func (e *stageError) Error() string { return e.Stage + ": " + e.Reason }

func main() {
	var opts options
	flag.StringVar(&opts.CandidateBinary, "candidate-bin", "", "prebuilt v0.2.1 candidate binary")
	flag.StringVar(&opts.RollbackBinary, "rollback-bin", "", "prebuilt v0.2.0 rollback binary")
	flag.StringVar(&opts.InputLock, "input-lock", "", "strict aegis.rollback-input-lock/v2 file")
	flag.StringVar(&opts.InputLockSHA256, "input-lock-sha256", "", "expected SHA-256 of the exact input lock bytes")
	flag.StringVar(&opts.RepoRoot, "repo-root", ".", "candidate repository root")
	flag.BoolVar(&opts.AllowDirtyIteration, "allow-dirty-iteration", false, "permit a dirty checkout and label evidence ITERATION_ONLY")
	flag.Parse()

	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, `rollback_drill_error stage=input code=unexpected_positional_arguments`)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, opts, os.Stdout); err != nil {
		var staged *stageError
		if errors.As(err, &staged) {
			fmt.Fprintf(os.Stderr, "rollback_drill_error stage=%s code=%s\n", staged.Stage, staged.Reason)
		} else {
			fmt.Fprintln(os.Stderr, `rollback_drill_error stage=internal code=drill_failed`)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, opts options, output io.Writer) error {
	startedAt := time.Now().UTC()
	if err := validateOptions(opts); err != nil {
		return err
	}
	inputLock, inputLockDigest, err := loadRollbackInputLock(opts.InputLock, opts.InputLockSHA256)
	if err != nil {
		return &stageError{Stage: "input_lock", Reason: "input_lock_invalid"}
	}
	identity, err := inspectCandidateIdentityContext(ctx, opts.RepoRoot, inputLock.CandidateSHA, opts.AllowDirtyIteration)
	if err != nil {
		return &stageError{Stage: "identity", Reason: "candidate_identity_invalid"}
	}
	runner, err := snapshotRunningRunner(inputLock, identity)
	if err != nil {
		return &stageError{Stage: "identity", Reason: "runner_identity_invalid"}
	}
	defer func() { _ = runner.close() }()

	root, err := os.MkdirTemp("", "aegis-rollback-drill-")
	if err != nil {
		return &stageError{Stage: "setup", Reason: "temporary_directory_failed"}
	}
	runCompleted := false
	defer func() {
		if !runCompleted {
			_ = os.RemoveAll(root)
		}
	}()
	if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- this is an owner-only directory, not a shared data file.
		return &stageError{Stage: "setup", Reason: "temporary_permissions_failed"}
	}
	snapshots, err := snapshotInputBinaries(opts)
	if err != nil {
		return &stageError{Stage: "identity", Reason: "binary_snapshot_failed"}
	}
	defer snapshots.close()
	if !digestMatches(snapshots.CandidateDigest, inputLock.CandidateBinarySHA256) {
		return &stageError{Stage: "identity", Reason: "candidate_digest_mismatch"}
	}
	if !digestMatches(snapshots.RollbackDigest, inputLock.RollbackBinarySHA256) {
		return &stageError{Stage: "identity", Reason: "rollback_digest_mismatch"}
	}
	if err := validateBinaryVersion(ctx, snapshots.Candidate, "v0.2.1", inputLock.CandidateSHA); err != nil {
		return &stageError{Stage: "identity", Reason: "candidate_version_mismatch"}
	}
	if err := validateBinaryVersion(ctx, snapshots.Rollback, "v0.2.0", rollbackV020SHA); err != nil {
		return &stageError{Stage: "identity", Reason: "rollback_version_mismatch"}
	}
	if err := validateAegisBuildInfoReader(snapshots.Candidate.file, inputLock.CandidateSHA, identity.Dirty); err != nil {
		return &stageError{Stage: "identity", Reason: "candidate_build_info_mismatch"}
	}
	if err := validateAegisBuildInfoReader(snapshots.Rollback.file, rollbackV020SHA, false); err != nil {
		return &stageError{Stage: "identity", Reason: "rollback_build_info_mismatch"}
	}

	secrets, err := newDrillSecrets()
	if err != nil {
		return &stageError{Stage: "setup", Reason: "secret_generation_failed"}
	}
	defer utils.MemZero(secrets.master)
	defer utils.MemZero(secrets.jwt)
	defer utils.MemZero(secrets.provider)

	provider, err := newFakeProvider(secrets.provider)
	if err != nil {
		return &stageError{Stage: "setup", Reason: "provider_listener_failed"}
	}
	provider.start()
	defer provider.close()
	caPath := filepath.Join(root, "provider-ca.pem")
	if err := writeProviderCA(caPath, provider.server.Certificate()); err != nil {
		return &stageError{Stage: "setup", Reason: "provider_ca_failed"}
	}

	keyStore := filepath.Join(root, "legacy-store")
	if err := os.Mkdir(keyStore, 0o700); err != nil {
		return &stageError{Stage: "setup", Reason: "legacy_store_failed"}
	}
	legacyBlob, err := createLegacyBlob(secrets.master, secrets.provider)
	if err != nil {
		return &stageError{Stage: "setup", Reason: "legacy_encryption_failed"}
	}
	defer utils.MemZero(legacyBlob)
	legacyPath := filepath.Join(keyStore, base64.RawURLEncoding.EncodeToString([]byte(drillProviderKeyID))+".key")
	if err := os.WriteFile(legacyPath, legacyBlob, 0o600); err != nil {
		return &stageError{Stage: "setup", Reason: "legacy_store_failed"}
	}
	preMigration, err := snapshotEncryptedDirectory(keyStore)
	if err != nil {
		return &stageError{Stage: "setup", Reason: "legacy_snapshot_failed"}
	}

	currentPort, err := unusedLoopbackPort()
	if err != nil {
		return &stageError{Stage: "setup", Reason: "current_port_failed"}
	}
	rollbackPort, err := unusedLoopbackPort()
	if err != nil {
		return &stageError{Stage: "setup", Reason: "rollback_port_failed"}
	}
	revocationPath := filepath.Join(root, "revocations.json")
	migrationConfig := filepath.Join(root, "candidate-migration.json")
	strictConfig := filepath.Join(root, "candidate-strict.json")
	oldConfigBackup := filepath.Join(root, "pre-migration-v0.2.0.json")
	rollbackConfig := filepath.Join(root, "restored-v0.2.0.json")
	if err := writeConfig(migrationConfig, configDocument(currentPort, provider.url(), keyStore, revocationPath, 1, true)); err != nil {
		return &stageError{Stage: "setup", Reason: "candidate_config_failed"}
	}
	if err := writeConfig(strictConfig, configDocument(currentPort, provider.url(), keyStore, revocationPath, 2, true)); err != nil {
		return &stageError{Stage: "setup", Reason: "candidate_config_failed"}
	}
	restoredStore := filepath.Join(root, "restored-v0.2.0-store")
	if err := writeConfig(oldConfigBackup, configDocument(rollbackPort, provider.url(), restoredStore, "", 0, false)); err != nil {
		return &stageError{Stage: "setup", Reason: "rollback_config_failed"}
	}
	oldConfigDigest, err := ownerOnlyFileDigest(oldConfigBackup)
	if err != nil {
		return &stageError{Stage: "setup", Reason: "rollback_config_digest_failed"}
	}

	childTemp := filepath.Join(root, "child-tmp")
	if err := os.Mkdir(childTemp, 0o700); err != nil {
		return &stageError{Stage: "setup", Reason: "child_temporary_directory_failed"}
	}
	childEnv := drillEnvironment(secrets, caPath, childTemp)
	if err := requireMigrationReport(ctx, snapshots.Candidate, migrationConfig, childEnv, true, "total=1 legacy=1 v2=0 migrated=0"); err != nil {
		return &stageError{Stage: "migration_dry_run", Reason: "candidate_command_failed"}
	}
	backupDir := filepath.Join(root, "encrypted-pre-migration-backup")
	if err := requireMigrationApply(ctx, snapshots.Candidate, migrationConfig, backupDir, childEnv); err != nil {
		return &stageError{Stage: "migration_apply", Reason: "candidate_command_failed"}
	}
	backupSnapshot, err := snapshotEncryptedDirectory(backupDir)
	if err != nil || !equalSnapshots(preMigration, backupSnapshot) {
		return &stageError{Stage: "migration_apply", Reason: "encrypted_backup_mismatch"}
	}
	if err := requireMigrationReport(ctx, snapshots.Candidate, migrationConfig, childEnv, true, "total=1 legacy=0 v2=1 migrated=0"); err != nil {
		return &stageError{Stage: "migration_verify", Reason: "candidate_command_failed"}
	}
	if err := runChild(ctx, snapshots.Candidate, childEnv, "operator", "revocation", "init", "--config", strictConfig); err != nil {
		return &stageError{Stage: "current_setup", Reason: "revocation_init_failed"}
	}
	tokenPath := filepath.Join(root, "virtual-key.jwt")
	if err := runChild(ctx, snapshots.Candidate, childEnv,
		"operator", "virtual-key", "issue", "--config", strictConfig,
		"--subject", "rollback-drill", "--models", drillModel, "--ttl", "10m",
		"--rpm", "60", "--max-concurrency", "2", "--out", tokenPath); err != nil {
		return &stageError{Stage: "current_setup", Reason: "token_issue_failed"}
	}
	token, err := readSecretFile(tokenPath)
	if err != nil {
		return &stageError{Stage: "current_setup", Reason: "token_read_failed"}
	}
	defer utils.MemZero(token)

	currentProcess, err := startGateway(snapshots.Candidate, strictConfig, childEnv)
	if err != nil {
		return &stageError{Stage: "current_start", Reason: "gateway_start_failed"}
	}
	defer func() { _ = currentProcess.stop() }()
	if err := smokeGateway(ctx, currentProcess, currentPort, token, provider); err != nil {
		code := smokeFailureCode(err)
		_ = currentProcess.stop()
		if code == "gateway_upstream_failed" {
			code = currentProcess.safeUpstreamFailureCode()
		}
		return &stageError{Stage: "current_smoke", Reason: code}
	}
	if err := currentProcess.stop(); err != nil {
		return &stageError{Stage: "current_stop", Reason: "gateway_stop_failed"}
	}

	if err := restoreEncryptedBackup(backupDir, restoredStore, backupSnapshot); err != nil {
		return &stageError{Stage: "rollback_restore", Reason: "encrypted_backup_restore_failed"}
	}
	if err := restoreOwnerOnlyFile(oldConfigBackup, rollbackConfig, oldConfigDigest); err != nil {
		return &stageError{Stage: "rollback_restore", Reason: "old_config_restore_failed"}
	}
	restoredConfigDigest, err := ownerOnlyFileDigest(rollbackConfig)
	if err != nil || restoredConfigDigest != oldConfigDigest {
		return &stageError{Stage: "rollback_restore", Reason: "old_config_restore_mismatch"}
	}
	restoredSnapshot, err := snapshotEncryptedDirectory(restoredStore)
	if err != nil || !equalSnapshots(preMigration, restoredSnapshot) {
		return &stageError{Stage: "rollback_restore", Reason: "encrypted_backup_restore_mismatch"}
	}
	rollbackProcess, err := startGateway(snapshots.Rollback, rollbackConfig, childEnv)
	if err != nil {
		return &stageError{Stage: "rollback_start", Reason: "gateway_start_failed"}
	}
	defer func() { _ = rollbackProcess.stop() }()
	if err := smokeGateway(ctx, rollbackProcess, rollbackPort, token, provider); err != nil {
		code := smokeFailureCode(err)
		_ = rollbackProcess.stop()
		if code == "gateway_upstream_failed" {
			code = rollbackProcess.safeUpstreamFailureCode()
		}
		return &stageError{Stage: "rollback_smoke", Reason: code}
	}
	if err := rollbackProcess.stop(); err != nil {
		return &stageError{Stage: "rollback_stop", Reason: "gateway_stop_failed"}
	}

	candidateAfter, err := snapshots.Candidate.digest()
	if err != nil || candidateAfter != snapshots.CandidateDigest {
		return &stageError{Stage: "identity", Reason: "candidate_snapshot_changed"}
	}
	rollbackAfter, err := snapshots.Rollback.digest()
	if err != nil || rollbackAfter != snapshots.RollbackDigest {
		return &stageError{Stage: "identity", Reason: "rollback_snapshot_changed"}
	}
	finalIdentity, err := inspectCandidateIdentityContext(ctx, opts.RepoRoot, inputLock.CandidateSHA, opts.AllowDirtyIteration)
	if err != nil || finalIdentity != identity {
		return &stageError{Stage: "identity", Reason: "candidate_repository_changed"}
	}
	runnerAfter, err := runner.currentDigest()
	if err != nil || !digestMatches(runnerAfter, runner.digest) {
		return &stageError{Stage: "identity", Reason: "runner_snapshot_changed"}
	}

	summary := successSummary{
		SchemaVersion:         3,
		Result:                "PASS",
		EvidenceClass:         identity.EvidenceClass,
		WorktreeClean:         !identity.Dirty,
		RunID:                 inputLock.RunID,
		ContainmentNonce:      inputLock.ContainmentNonce,
		StartedAt:             canonicalUTCTimestamp(startedAt),
		EndedAt:               "", // Filled only after temporary cleanup succeeds.
		RunnerBinarySHA256:    runner.digest,
		CandidateSHA:          inputLock.CandidateSHA,
		RollbackSourceSHA:     rollbackV020SHA,
		CandidateBinarySHA256: snapshots.CandidateDigest,
		RollbackBinarySHA256:  snapshots.RollbackDigest,
		InputLockDigest:       inputLockDigest,
		Migration:             "legacy_file_store_to_v2_strict_pass",
		CurrentSmoke:          "health_auth_kms_tls_provider_200_pass",
		Rollback:              "encrypted_backup_restore_v0.2.0_health_auth_kms_tls_provider_200_pass",
	}
	if err := writeSummaryAfterCleanup(root, output, summary, os.RemoveAll); err != nil {
		return err
	}
	runCompleted = true
	return nil
}

func digestMatches(actual, expected string) bool {
	return len(actual) == sha256.Size*2 && len(expected) == sha256.Size*2 &&
		subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

func snapshotRunningRunner(lock rollbackInputLock, identity candidateIdentity) (*runnerSnapshot, error) {
	// /proc/self/exe resolves to the executable inode of this running process,
	// even if the caller-selected path used to launch it is later replaced.
	file, err := os.Open(rollbackRunnerExecutablePath) // #nosec G304 -- fixed Linux self-executable pseudo-path, never caller controlled.
	if err != nil {
		return nil, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxInputBinaryBytes {
		return nil, errors.New("runner executable is not a bounded regular file")
	}
	snapshot := &runnerSnapshot{file: file, size: info.Size()}
	digest, err := snapshot.currentDigest()
	if err != nil || !digestMatches(digest, lock.RunnerBinarySHA256) {
		return nil, errors.New("runner executable digest mismatch")
	}
	if err := validateRollbackRunnerBuildInfoReader(file, lock.CandidateSHA, identity.Dirty); err != nil {
		return nil, err
	}
	snapshot.digest = digest
	closed = true
	return snapshot, nil
}

func validateRollbackRunnerBuildInfoReader(reader io.ReaderAt, sha string, modified bool) error {
	fileInfo, err := buildinfo.Read(reader)
	if err != nil {
		return err
	}
	return validateRollbackRunnerBuildInfo(fileInfo, sha, modified)
}

func validateRollbackRunnerBuildInfo(fileInfo *debug.BuildInfo, sha string, modified bool) error {
	if fileInfo == nil || fileInfo.Path != aegisRollbackRunnerPackagePath || fileInfo.Main.Path != aegisModulePath {
		return errors.New("rollback runner module identity mismatch")
	}
	return validateVCSBuildSettings(fileInfo.Settings, sha, modified)
}

func validateOptions(opts options) error {
	if hostGOOS != "linux" {
		return &stageError{Stage: "input", Reason: "linux_host_required"}
	}
	if opts.CandidateBinary == "" || opts.RollbackBinary == "" || opts.RepoRoot == "" || opts.InputLock == "" || opts.InputLockSHA256 == "" {
		return &stageError{Stage: "input", Reason: "required_flag_missing"}
	}
	if !fullSHA256.MatchString(opts.InputLockSHA256) {
		return &stageError{Stage: "input", Reason: "input_lock_sha256_not_full"}
	}
	return nil
}

func snapshotInputBinaries(opts options) (binarySnapshot, error) {
	candidate, candidateDigest, err := snapshotExecutable(opts.CandidateBinary, "candidate")
	if err != nil {
		return binarySnapshot{}, err
	}
	rollback, rollbackDigest, err := snapshotExecutable(opts.RollbackBinary, "rollback-v0.2.0")
	if err != nil {
		_ = candidate.close()
		return binarySnapshot{}, err
	}
	afterBinarySnapshotHook()
	return binarySnapshot{
		Candidate: candidate, Rollback: rollback,
		CandidateDigest: candidateDigest, RollbackDigest: rollbackDigest,
	}, nil
}

func snapshotExecutable(source, label string) (*sealedExecutable, string, error) {
	fd, err := syscall.Open(source, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- O_NOFOLLOW protects the explicit release input.
	if err != nil {
		return nil, "", err
	}
	input := os.NewFile(uintptr(fd), "release-input")
	if input == nil {
		_ = syscall.Close(fd)
		return nil, "", errors.New("opening release input")
	}
	defer func() { _ = input.Close() }()
	before, err := input.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode()&0o111 == 0 || before.Size() < 1 || before.Size() > maxInputBinaryBytes {
		return nil, "", errors.New("release input is not a bounded regular executable")
	}
	output, err := newSealableExecutable(label)
	if err != nil {
		return nil, "", err
	}
	outputClosed := false
	defer func() {
		if !outputClosed {
			_ = output.Close()
		}
	}()
	hash := sha256.New()
	written, copyErr := io.CopyN(io.MultiWriter(output, hash), input, before.Size())
	if copyErr == nil && written != before.Size() {
		copyErr = io.ErrUnexpectedEOF
	}
	var one [1]byte
	if copyErr == nil {
		if n, readErr := input.Read(one[:]); n != 0 || !errors.Is(readErr, io.EOF) {
			copyErr = errors.New("release input grew during snapshot")
		}
	}
	after, statErr := input.Stat()
	if statErr != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		copyErr = errors.New("release input changed during snapshot")
	}
	if syncErr := output.Sync(); copyErr == nil && syncErr != nil {
		copyErr = syncErr
	}
	if copyErr != nil {
		return nil, "", copyErr
	}
	sealedFile, err := sealAndReopenExecutable(output)
	if err != nil {
		return nil, "", err
	}
	if err := output.Close(); err != nil {
		_ = sealedFile.Close()
		return nil, "", err
	}
	outputClosed = true
	sealed := &sealedExecutable{file: sealedFile, size: before.Size()}
	digest := hex.EncodeToString(hash.Sum(nil))
	sealedDigest, err := sealed.digest()
	if err != nil || !digestMatches(sealedDigest, digest) {
		_ = sealed.close()
		return nil, "", errors.New("sealed executable digest mismatch")
	}
	return sealed, digest, nil
}

func validateCandidateIdentity(repo, sha string, allowDirty bool) error {
	_, err := inspectCandidateIdentity(repo, sha, allowDirty)
	return err
}

func inspectCandidateIdentity(repo, sha string, allowDirty bool) (candidateIdentity, error) {
	return inspectCandidateIdentityContext(context.Background(), repo, sha, allowDirty)
}

func inspectCandidateIdentityContext(ctx context.Context, repo, sha string, allowDirty bool) (candidateIdentity, error) {
	if !fullSHA.MatchString(sha) {
		return candidateIdentity{}, errors.New("candidate SHA must be 40 lowercase hexadecimal characters")
	}
	repository, err := openCandidateRepository(repo)
	if err != nil {
		return candidateIdentity{}, errors.New("cannot inspect repository worktree")
	}
	defer repository.close()

	objectFormat, err := repository.gitSingleLine(ctx, "rev-parse", "--show-object-format")
	if err != nil || objectFormat != "sha1" {
		return candidateIdentity{}, errors.New("candidate repository object format is unsupported")
	}
	if err := repository.rejectPromisorConfiguration(ctx); err != nil {
		return candidateIdentity{}, errors.New("candidate repository object storage is unsupported")
	}
	head, err := repository.gitSingleLine(ctx, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil || head != sha || !fullSHA.MatchString(head) {
		return candidateIdentity{}, errors.New("candidate SHA does not match repository HEAD")
	}
	treeOutput, stderr, err := repository.gitOutput(ctx, maxCandidateTreeOutputBytes,
		"ls-tree", "-rz", "-l", "--full-tree", sha)
	if err != nil || stderr != "" {
		return candidateIdentity{}, errors.New("cannot inspect candidate repository tree")
	}
	tree, err := parseCandidateTreeOutput([]byte(treeOutput))
	if err != nil {
		return candidateIdentity{}, errors.New("cannot inspect candidate repository tree")
	}
	snapshot, err := snapshotCandidateWorktree(ctx, repository.worktree)
	if err != nil {
		return candidateIdentity{}, errors.New("cannot inspect repository worktree")
	}
	dirty, err := compareCandidateTree(tree, snapshot)
	if err != nil {
		return candidateIdentity{}, errors.New("cannot inspect repository worktree")
	}
	digest, err := candidateWorktreeDigest(snapshot)
	if err != nil {
		return candidateIdentity{}, errors.New("cannot inspect repository worktree")
	}
	if err := repository.verify(); err != nil {
		return candidateIdentity{}, errors.New("cannot inspect repository worktree")
	}
	if dirty && !allowDirty {
		return candidateIdentity{}, errors.New("candidate repository is not clean")
	}
	class := evidenceFinal
	if dirty {
		class = evidenceIterationOnly
	}
	return candidateIdentity{Dirty: dirty, EvidenceClass: class, WorktreeDigest: digest}, nil
}

func openCandidateRepository(repo string) (*candidateRepository, error) {
	worktree, canonicalPath, err := openCanonicalDirectory(repo)
	if err != nil {
		return nil, err
	}
	worktreeInfo, err := worktree.Stat()
	if err != nil || !secureCandidateDirectory(worktreeInfo) {
		_ = worktree.Close()
		return nil, errors.New("candidate worktree directory is unsafe")
	}
	gitDir, err := openFileAt(worktree, ".git",
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_DIRECTORY, 0)
	if err != nil {
		_ = worktree.Close()
		return nil, err
	}
	gitDirInfo, err := gitDir.Stat()
	if err != nil || !secureCandidateDirectory(gitDirInfo) {
		_ = gitDir.Close()
		_ = worktree.Close()
		return nil, errors.New("candidate Git directory is unsafe")
	}
	if err := rejectLinkedGitDirectory(gitDir); err != nil {
		_ = gitDir.Close()
		_ = worktree.Close()
		return nil, err
	}
	if err := rejectUnsafeGitObjectLayout(gitDir); err != nil {
		_ = gitDir.Close()
		_ = worktree.Close()
		return nil, err
	}
	return &candidateRepository{path: canonicalPath, worktree: worktree, gitDir: gitDir}, nil
}

func openCanonicalDirectory(rawPath string) (*os.File, string, error) {
	if rawPath == "" || strings.IndexByte(rawPath, 0) >= 0 {
		return nil, "", errors.New("candidate repository path is invalid")
	}
	canonicalPath, err := filepath.Abs(rawPath)
	if err != nil {
		return nil, "", err
	}
	canonicalPath = filepath.Clean(canonicalPath)
	if canonicalPath == string(filepath.Separator) {
		return nil, "", errors.New("candidate repository path is too broad")
	}

	current, err := os.Open(string(filepath.Separator))
	if err != nil {
		return nil, "", err
	}
	components := strings.Split(strings.TrimPrefix(canonicalPath, string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			_ = current.Close()
			return nil, "", errors.New("candidate repository path is not canonical")
		}
		next, openErr := openFileAt(current, component,
			syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_DIRECTORY, 0)
		_ = current.Close()
		if openErr != nil {
			return nil, "", openErr
		}
		current = next
	}
	return current, canonicalPath, nil
}

func secureCandidateDirectory(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode().Perm()&0o022 == 0 &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && ownedByCurrentUser(info)
}

func rejectLinkedGitDirectory(gitDir *os.File) error {
	commonDir, err := openFileAt(gitDir, "commondir",
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err == nil {
		_ = commonDir.Close()
		return errors.New("linked Git directories are unsupported")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func rejectUnsafeGitObjectLayout(gitDir *os.File) error {
	for _, components := range [][]string{
		{"objects", "info", "alternates"},
		{"objects", "info", "http-alternates"},
		{"info", "grafts"},
	} {
		exists, err := candidateEntryExistsAt(gitDir, components...)
		if err != nil {
			return err
		}
		if exists {
			return errors.New("candidate Git object layout is unsupported")
		}
	}
	packDirectory, err := openCandidateSubdirectory(gitDir, "objects", "pack")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = packDirectory.Close() }()
	entries, err := readCandidateDirectoryEntries(packDirectory, false)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".promisor") {
			return errors.New("candidate Git promisor objects are unsupported")
		}
	}
	return nil
}

func candidateEntryExistsAt(root *os.File, components ...string) (bool, error) {
	if root == nil || len(components) == 0 {
		return false, errors.New("candidate Git entry path is invalid")
	}
	parent := root
	parentOwned := false
	for _, component := range components[:len(components)-1] {
		next, err := openFileAt(parent, component,
			syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_DIRECTORY, 0)
		if parentOwned {
			_ = parent.Close()
		}
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		parent = next
		parentOwned = true
	}
	if parentOwned {
		defer func() { _ = parent.Close() }()
	}
	_, err := entryInfoAt(parent, components[len(components)-1], 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func openCandidateSubdirectory(root *os.File, components ...string) (*os.File, error) {
	if root == nil || len(components) == 0 {
		return nil, errors.New("candidate Git directory path is invalid")
	}
	parent := root
	parentOwned := false
	for _, component := range components {
		next, err := openFileAt(parent, component,
			syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_DIRECTORY, 0)
		if parentOwned {
			_ = parent.Close()
		}
		if err != nil {
			return nil, err
		}
		parent = next
		parentOwned = true
	}
	return parent, nil
}

func (r *candidateRepository) close() {
	if r == nil {
		return
	}
	if r.gitDir != nil {
		_ = r.gitDir.Close()
	}
	if r.worktree != nil {
		_ = r.worktree.Close()
	}
}

func (r *candidateRepository) verify() error {
	if r == nil || r.worktree == nil || r.gitDir == nil {
		return errors.New("candidate repository is not open")
	}
	worktreeInfo, err := r.worktree.Stat()
	if err != nil || !secureCandidateDirectory(worktreeInfo) {
		return errors.New("candidate worktree directory changed")
	}
	gitDirInfo, err := r.gitDir.Stat()
	if err != nil || !secureCandidateDirectory(gitDirInfo) {
		return errors.New("candidate Git directory changed")
	}
	reopened, _, err := openCanonicalDirectory(r.path)
	if err != nil {
		return err
	}
	defer func() { _ = reopened.Close() }()
	reopenedInfo, err := reopened.Stat()
	if err != nil || !os.SameFile(worktreeInfo, reopenedInfo) {
		return errors.New("candidate worktree path changed")
	}
	reopenedGitDir, err := openFileAt(reopened, ".git",
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = reopenedGitDir.Close() }()
	reopenedGitDirInfo, err := reopenedGitDir.Stat()
	if err != nil || !os.SameFile(gitDirInfo, reopenedGitDirInfo) || !secureCandidateDirectory(reopenedGitDirInfo) {
		return errors.New("candidate Git directory path changed")
	}
	if err := rejectLinkedGitDirectory(reopenedGitDir); err != nil {
		return err
	}
	return rejectUnsafeGitObjectLayout(reopenedGitDir)
}

func inheritedDirectoryPath(descriptor int) string {
	prefix := "/proc/self/fd/"
	if runtime.GOOS == "darwin" {
		prefix = "/dev/fd/"
	}
	return prefix + strconv.Itoa(descriptor)
}

func candidateGitEnvironment() []string {
	return []string{
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_NO_LAZY_FETCH=1",
		"GIT_NO_REPLACE_OBJECTS=1",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_PAGER=cat",
		"GIT_TERMINAL_PROMPT=0",
		"HOME=/nonexistent",
		"LANG=C",
		"LC_ALL=C",
		"PAGER=cat",
		"PATH=/usr/bin:/bin",
		"TZ=UTC",
	}
}

func (r *candidateRepository) gitOutput(ctx context.Context, outputLimit int, args ...string) (string, string, error) {
	if r == nil || r.worktree == nil || r.gitDir == nil {
		return "", "", errors.New("candidate repository is not open")
	}
	gitArgs := []string{
		"--git-dir=" + inheritedDirectoryPath(3),
		"--work-tree=" + inheritedDirectoryPath(4),
		"--no-pager",
	}
	cmd := exec.Command(trustedGitPath, append(gitArgs, args...)...) // #nosec G204 -- fixed absolute Git binary, descriptor-anchored repository, and constant production arguments.
	cmd.ExtraFiles = []*os.File{r.gitDir, r.worktree}
	return runBoundedCommandWithOutputLimit(ctx, 15*time.Second, cmd, candidateGitEnvironment(), outputLimit)
}

func (r *candidateRepository) gitSingleLine(ctx context.Context, args ...string) (string, error) {
	stdout, stderr, err := r.gitOutput(ctx, maxChildOutputBytes, args...)
	if err != nil || stderr != "" || strings.Contains(stdout, "\r") || strings.Count(stdout, "\n") != 1 || !strings.HasSuffix(stdout, "\n") {
		return "", errors.New("git metadata output is invalid")
	}
	return strings.TrimSuffix(stdout, "\n"), nil
}

func (r *candidateRepository) rejectPromisorConfiguration(ctx context.Context) error {
	for _, args := range [][]string{
		{"config", "--local", "--no-includes", "--get", "extensions.partialClone"},
		{"config", "--local", "--no-includes", "--get-regexp", `^remote\..*\.promisor$`},
	} {
		present, err := r.gitConfigurationPresent(ctx, args...)
		if err != nil {
			return err
		}
		if present {
			return errors.New("candidate Git promisor configuration is unsupported")
		}
	}
	return nil
}

func (r *candidateRepository) gitConfigurationPresent(ctx context.Context, args ...string) (bool, error) {
	stdout, stderr, err := r.gitOutput(ctx, maxChildOutputBytes, args...)
	if err == nil {
		if stderr != "" || stdout == "" {
			return false, errors.New("git configuration output is invalid")
		}
		return true, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == 1 && stdout == "" && stderr == "" {
		return false, nil
	}
	return false, err
}

func snapshotCandidateWorktree(ctx context.Context, worktree *os.File) (candidateWorktreeSnapshot, error) {
	snapshot := candidateWorktreeSnapshot{Entries: make(map[string]candidateWorktreeEntry)}
	if worktree == nil {
		return candidateWorktreeSnapshot{}, errors.New("candidate worktree is not open")
	}
	if err := walkCandidateDirectory(ctx, worktree, "", &snapshot); err != nil {
		return candidateWorktreeSnapshot{}, err
	}
	return snapshot, nil
}

func walkCandidateDirectory(ctx context.Context, directory *os.File, prefix string, snapshot *candidateWorktreeSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := directory.Stat()
	if err != nil || !before.IsDir() {
		return errors.New("candidate worktree directory is invalid")
	}
	entries, err := readCandidateDirectoryEntries(directory, prefix == "")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if prefix == "" && name == ".git" {
			continue
		}
		entryPath := name
		if prefix != "" {
			entryPath = prefix + "/" + name
		}
		if err := validateCandidatePath(entryPath); err != nil {
			return err
		}

		entryType := entry.Type()
		if entryType.Type() != 0 && !entryType.IsDir() && entryType&os.ModeSymlink == 0 {
			return errors.New("candidate worktree contains an unsupported file type")
		}
		entryInfo, infoErr := entryInfoAt(directory, name, entryType)
		if infoErr != nil || !secureCandidateEntry(entryInfo) {
			return errors.New("candidate worktree entry is unsafe")
		}
		entryInfoType := entryInfo.Mode().Type()
		if entryInfoType != 0 && !entryInfo.IsDir() && entryInfoType&os.ModeSymlink == 0 {
			return errors.New("candidate worktree contains an unsupported file type")
		}
		if entryInfoType&os.ModeSymlink != 0 {
			target, readErr := readlinkAt(directory, name, maxCandidateSymlinkBytes)
			if readErr != nil {
				return readErr
			}
			targetAgain, readErr := readlinkAt(directory, name, maxCandidateSymlinkBytes)
			afterInfo, infoErr := entryInfoAt(directory, name, entryType)
			if readErr != nil || infoErr != nil || !bytes.Equal(target, targetAgain) || !stableOpenedMetadata(entryInfo, afterInfo) {
				return errors.New("candidate symbolic link changed while being read")
			}
			worktreeEntry := candidateWorktreeEntry{
				Path:          entryPath,
				Mode:          "120000",
				ObjectID:      gitBlobObjectID(target),
				ContentDigest: contentSHA256(target),
				Size:          int64(len(target)),
				RawMode:       uint32(entryInfo.Mode()),
			}
			if err := snapshot.add(worktreeEntry); err != nil {
				return err
			}
			continue
		}
		opened, openErr := openFileAt(directory, name,
			syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if openErr != nil {
			return openErr
		}
		info, statErr := opened.Stat()
		if statErr != nil || !os.SameFile(entryInfo, info) || !secureCandidateEntry(info) {
			_ = opened.Close()
			return errors.New("candidate worktree entry changed while being opened")
		}
		switch {
		case info.IsDir():
			worktreeEntry := candidateWorktreeEntry{Path: entryPath, Mode: "040000", RawMode: uint32(info.Mode())}
			if err := snapshot.add(worktreeEntry); err != nil {
				_ = opened.Close()
				return err
			}
			walkErr := walkCandidateDirectory(ctx, opened, entryPath, snapshot)
			closeErr := opened.Close()
			if walkErr != nil {
				return walkErr
			}
			if closeErr != nil {
				return closeErr
			}
		case info.Mode().IsRegular():
			worktreeEntry, readErr := readCandidateRegularFile(opened, entryPath, info, snapshot.AggregateBytes)
			closeErr := opened.Close()
			if readErr != nil {
				return readErr
			}
			if closeErr != nil {
				return closeErr
			}
			if err := snapshot.add(worktreeEntry); err != nil {
				return err
			}
		default:
			_ = opened.Close()
			return errors.New("candidate worktree contains an unsupported file type")
		}
	}
	after, err := directory.Stat()
	if err != nil || !stableOpenedMetadata(before, after) {
		return errors.New("candidate worktree directory changed while being read")
	}
	return nil
}

func readCandidateDirectoryEntries(directory *os.File, root bool) ([]os.DirEntry, error) {
	limit := maxCandidateWorktreeEntries
	if root {
		limit++ // The pinned root .git entry is deliberately outside the worktree identity.
	}
	entries := make([]os.DirEntry, 0, 64)
	for {
		batch, err := directory.ReadDir(256)
		if len(entries) > limit-len(batch) {
			return nil, errors.New("candidate worktree entry count exceeds limit")
		}
		entries = append(entries, batch...)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func readCandidateRegularFile(file *os.File, entryPath string, before os.FileInfo, aggregateBytes int64) (candidateWorktreeEntry, error) {
	if before.Size() < 0 || before.Size() > maxCandidateBlobBytes || aggregateBytes > maxCandidateAggregateBytes-before.Size() {
		return candidateWorktreeEntry{}, errors.New("candidate worktree byte size exceeds limit")
	}
	// #nosec G401,G505 -- SHA-1 is required only to reproduce Git's existing blob object identity, never as a security signature.
	objectHash := sha1.New()
	header := "blob " + strconv.FormatInt(before.Size(), 10) + "\x00"
	if _, err := io.WriteString(objectHash, header); err != nil {
		return candidateWorktreeEntry{}, err
	}
	contentHash := sha256.New()
	written, err := io.CopyN(io.MultiWriter(objectHash, contentHash), file, before.Size())
	if err != nil || written != before.Size() {
		return candidateWorktreeEntry{}, errors.New("candidate worktree file changed while being read")
	}
	var extra [1]byte
	if n, readErr := file.Read(extra[:]); n != 0 || !errors.Is(readErr, io.EOF) {
		return candidateWorktreeEntry{}, errors.New("candidate worktree file grew while being read")
	}
	after, err := file.Stat()
	if err != nil || !stableOpenedMetadata(before, after) {
		return candidateWorktreeEntry{}, errors.New("candidate worktree file changed while being read")
	}
	mode := "100644"
	if before.Mode().Perm()&0o111 != 0 {
		mode = "100755"
	}
	return candidateWorktreeEntry{
		Path:          entryPath,
		Mode:          mode,
		ObjectID:      hex.EncodeToString(objectHash.Sum(nil)),
		ContentDigest: hex.EncodeToString(contentHash.Sum(nil)),
		Size:          before.Size(),
		RawMode:       uint32(before.Mode()),
	}, nil
}

func stableOpenedMetadata(before, after os.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) &&
		before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func secureCandidateEntry(info os.FileInfo) bool {
	if info == nil || !ownedByCurrentUser(info) || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	return info.Mode().Perm()&0o022 == 0
}

func gitBlobObjectID(content []byte) string {
	// #nosec G401,G505 -- SHA-1 is required only to reproduce Git's existing blob object identity, never as a security signature.
	hash := sha1.New()
	_, _ = io.WriteString(hash, "blob "+strconv.Itoa(len(content))+"\x00")
	_, _ = hash.Write(content)
	return hex.EncodeToString(hash.Sum(nil))
}

func contentSHA256(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func (s *candidateWorktreeSnapshot) add(entry candidateWorktreeEntry) error {
	if s == nil || s.Entries == nil {
		return errors.New("candidate worktree snapshot is invalid")
	}
	if s.EntryCount >= maxCandidateWorktreeEntries || len(entry.Path) > maxCandidatePathBytes ||
		s.AggregatePathLen > maxCandidateWorktreePathBytes-len(entry.Path) {
		return errors.New("candidate worktree path budget exceeds limit")
	}
	if entry.Size < 0 || entry.Size > maxCandidateBlobBytes || s.AggregateBytes > maxCandidateAggregateBytes-entry.Size {
		return errors.New("candidate worktree byte size exceeds limit")
	}
	if _, exists := s.Entries[entry.Path]; exists {
		return errors.New("candidate worktree path is duplicated")
	}
	s.Entries[entry.Path] = entry
	s.EntryCount++
	s.AggregatePathLen += len(entry.Path)
	s.AggregateBytes += entry.Size
	return nil
}

func compareCandidateTree(tree []candidateTreeEntry, snapshot candidateWorktreeSnapshot) (bool, error) {
	expectedBlobs := make(map[string]candidateTreeEntry, len(tree))
	expectedDirectories := make(map[string]struct{})
	for _, entry := range tree {
		if entry.Mode == "120000" && entry.Size > maxCandidateSymlinkBytes {
			return false, errors.New("candidate symbolic link target exceeds limit")
		}
		expectedBlobs[entry.Path] = entry
		parent := path.Dir(entry.Path)
		for parent != "." {
			expectedDirectories[parent] = struct{}{}
			parent = path.Dir(parent)
		}
	}
	if len(expectedBlobs)+len(expectedDirectories) > maxCandidateWorktreeEntries {
		return false, errors.New("candidate tree topology exceeds limit")
	}

	dirty := false
	for entryPath, expected := range expectedBlobs {
		actual, exists := snapshot.Entries[entryPath]
		if !exists || actual.Mode != expected.Mode || actual.Size != expected.Size || actual.ObjectID != expected.ObjectID {
			dirty = true
		}
	}
	for directoryPath := range expectedDirectories {
		actual, exists := snapshot.Entries[directoryPath]
		if !exists || actual.Mode != "040000" {
			dirty = true
		}
	}
	for entryPath, actual := range snapshot.Entries {
		if actual.Mode == "040000" {
			if _, exists := expectedDirectories[entryPath]; !exists {
				dirty = true
			}
			continue
		}
		if _, exists := expectedBlobs[entryPath]; !exists {
			dirty = true
		}
	}
	return dirty, nil
}

func candidateWorktreeDigest(snapshot candidateWorktreeSnapshot) (string, error) {
	paths := make([]string, 0, len(snapshot.Entries))
	for entryPath := range snapshot.Entries {
		paths = append(paths, entryPath)
	}
	sort.Strings(paths)
	hash := sha256.New()
	_, _ = io.WriteString(hash, "aegis-worktree-identity-v1\x00")
	for _, entryPath := range paths {
		entry := snapshot.Entries[entryPath]
		if entry.Size < 0 {
			return "", errors.New("candidate worktree digest entry size is invalid")
		}
		fields := []string{
			entry.Path,
			entry.Mode,
			entry.ContentDigest,
			strconv.FormatInt(entry.Size, 10),
			strconv.FormatUint(uint64(entry.RawMode), 10),
		}
		for _, field := range fields {
			_, _ = io.WriteString(hash, strconv.Itoa(len(field)))
			_, _ = hash.Write([]byte{':'})
			_, _ = io.WriteString(hash, field)
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func parseCandidateTreeOutput(output []byte) ([]candidateTreeEntry, error) {
	if len(output) > maxCandidateTreeOutputBytes {
		return nil, errors.New("candidate tree output exceeds byte limit")
	}
	if len(output) == 0 {
		return []candidateTreeEntry{}, nil
	}
	if output[len(output)-1] != 0 {
		return nil, errors.New("candidate tree output is not NUL terminated")
	}

	records := bytes.Split(output[:len(output)-1], []byte{0})
	if len(records) > maxCandidateTreeEntries {
		return nil, errors.New("candidate tree entry count exceeds limit")
	}
	entries := make([]candidateTreeEntry, 0, len(records))
	seenPaths := make(map[string]struct{}, len(records))
	var aggregateBytes int64
	for _, record := range records {
		if len(record) == 0 {
			return nil, errors.New("candidate tree contains an empty record")
		}
		tab := bytes.IndexByte(record, '\t')
		if tab < 1 || bytes.IndexByte(record[tab+1:], '\t') >= 0 {
			return nil, errors.New("candidate tree record framing is invalid")
		}
		metadata := strings.Fields(string(record[:tab]))
		if len(metadata) != 4 {
			return nil, errors.New("candidate tree metadata is invalid")
		}
		mode, objectType, objectID, sizeText := metadata[0], metadata[1], metadata[2], metadata[3]
		switch mode {
		case "100644", "100755", "120000":
		default:
			return nil, errors.New("candidate tree mode is unsupported")
		}
		if objectType != "blob" {
			return nil, errors.New("candidate tree object type is unsupported")
		}
		if !fullSHA.MatchString(objectID) {
			return nil, errors.New("candidate tree object id is invalid")
		}
		size, err := strconv.ParseInt(sizeText, 10, 64)
		if err != nil || size < 0 || strconv.FormatInt(size, 10) != sizeText {
			return nil, errors.New("candidate tree blob size is invalid")
		}
		if size > maxCandidateBlobBytes || aggregateBytes > maxCandidateAggregateBytes-size {
			return nil, errors.New("candidate tree blob size exceeds limit")
		}
		aggregateBytes += size

		pathBytes := record[tab+1:]
		if len(pathBytes) == 0 || !utf8.Valid(pathBytes) {
			return nil, errors.New("candidate tree path is invalid")
		}
		entryPath := string(pathBytes)
		if err := validateCandidatePath(entryPath); err != nil {
			return nil, err
		}
		if _, exists := seenPaths[entryPath]; exists {
			return nil, errors.New("candidate tree path is duplicated")
		}
		seenPaths[entryPath] = struct{}{}
		entries = append(entries, candidateTreeEntry{Path: entryPath, Mode: mode, ObjectID: objectID, Size: size})
	}
	for entryPath := range seenPaths {
		for parent := path.Dir(entryPath); parent != "."; parent = path.Dir(parent) {
			if _, conflicts := seenPaths[parent]; conflicts {
				return nil, errors.New("candidate tree path topology is invalid")
			}
		}
	}
	return entries, nil
}

func validateCandidatePath(entryPath string) error {
	if entryPath == "" || len(entryPath) > maxCandidatePathBytes || !utf8.ValidString(entryPath) ||
		path.IsAbs(entryPath) || path.Clean(entryPath) != entryPath || strings.Contains(entryPath, "\\") {
		return errors.New("candidate tree path is not canonical")
	}
	components := strings.Split(entryPath, "/")
	if len(components) > maxCandidateTreeDepth {
		return errors.New("candidate tree path depth exceeds limit")
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." || component == ".git" {
			return errors.New("candidate tree path is not canonical")
		}
		for _, character := range component {
			if character < 0x20 || character == 0x7f {
				return errors.New("candidate tree path contains control characters")
			}
		}
	}
	return nil
}

func validateBinaryVersion(ctx context.Context, executable *sealedExecutable, version, sha string) error {
	stdout, _, err := runBoundedProcess(ctx, 10*time.Second, executable, identityEnvironment(), "--version")
	if err != nil {
		return err
	}
	return validateVersionOutput(stdout, version, sha)
}

func validateVersionOutput(output, version, sha string) error {
	if strings.Count(output, "\n") != 1 || !strings.HasSuffix(output, "\n") || strings.Contains(output, "\r") {
		return errors.New("version output must be exactly one newline-terminated line")
	}
	line := strings.TrimSuffix(output, "\n")
	prefix := "aegis " + version + " (commit: " + sha + ", built: "
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, ")") {
		return errors.New("version identity mismatch")
	}
	built := strings.TrimSuffix(strings.TrimPrefix(line, prefix), ")")
	if built == "" || len(built) > 128 {
		return errors.New("version build identifier is invalid")
	}
	for _, character := range built {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:+-", character) {
			return errors.New("version build identifier is invalid")
		}
	}
	return nil
}

func identityEnvironment() []string {
	return []string{
		"HOME=/nonexistent",
		"LANG=C",
		"PATH=/usr/bin:/bin",
		"TZ=UTC",
	}
}

func validateAegisBuildInfoReader(reader io.ReaderAt, sha string, modified bool) error {
	fileInfo, err := buildinfo.Read(reader)
	if err != nil {
		return err
	}
	return validateAegisBuildInfo(fileInfo, sha, modified)
}

func validateAegisBuildInfo(fileInfo *debug.BuildInfo, sha string, modified bool) error {
	if fileInfo == nil || fileInfo.Path != aegisMainPackagePath || fileInfo.Main.Path != aegisModulePath {
		return errors.New("aegis module identity mismatch")
	}
	return validateVCSBuildSettings(fileInfo.Settings, sha, modified)
}

func validateVCSBuildSettings(buildSettings []debug.BuildSetting, sha string, modified bool) error {
	settings := make(map[string]string, len(buildSettings))
	counts := make(map[string]int, 2)
	for _, setting := range buildSettings {
		if setting.Key == "vcs.revision" || setting.Key == "vcs.modified" {
			settings[setting.Key] = setting.Value
			counts[setting.Key]++
		}
	}
	if counts["vcs.revision"] != 1 || settings["vcs.revision"] != sha {
		return errors.New("build vcs revision mismatch")
	}
	wantModified := "false"
	if modified {
		wantModified = "true"
	}
	if counts["vcs.modified"] != 1 || settings["vcs.modified"] != wantModified {
		return errors.New("build dirty state mismatch")
	}
	return nil
}

type drillSecrets struct {
	master   []byte
	jwt      []byte
	provider []byte
}

func newDrillSecrets() (*drillSecrets, error) {
	result := &drillSecrets{master: make([]byte, 32), jwt: make([]byte, 32), provider: make([]byte, 64)}
	for _, secret := range [][]byte{result.master, result.jwt} {
		if _, err := io.ReadFull(rand.Reader, secret); err != nil {
			utils.MemZero(result.master)
			utils.MemZero(result.jwt)
			utils.MemZero(result.provider)
			return nil, err
		}
	}
	providerEntropy := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, providerEntropy); err != nil {
		utils.MemZero(providerEntropy)
		utils.MemZero(result.master)
		utils.MemZero(result.jwt)
		utils.MemZero(result.provider)
		return nil, err
	}
	hex.Encode(result.provider, providerEntropy)
	utils.MemZero(providerEntropy)
	return result, nil
}

func createLegacyBlob(masterKey, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

type fakeProvider struct {
	server   *httptest.Server
	expected []byte
	attempts atomic.Int64
	hits     atomic.Int64
}

func newFakeProvider(providerSecret []byte) (*fakeProvider, error) {
	provider := &fakeProvider{expected: append([]byte("Bearer "), providerSecret...)}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		utils.MemZero(provider.expected)
		return nil, err
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider.attempts.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" ||
			subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), provider.expected) != 1 {
			http.Error(w, "provider request rejected", http.StatusUnauthorized)
			return
		}
		provider.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"id":"rollback-drill","object":"chat.completion","choices":[]}`)
	})
	server := &httptest.Server{
		Listener: listener,
		Config: &http.Server{
			Handler:           handler,
			ErrorLog:          log.New(io.Discard, "", 0),
			ReadHeaderTimeout: 2 * time.Second,
		},
	}
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	provider.server = server
	return provider, nil
}

func (p *fakeProvider) start() { p.server.StartTLS() }
func (p *fakeProvider) close() {
	p.server.Close()
	utils.MemZero(p.expected)
}
func (p *fakeProvider) url() string { return p.server.URL }

func writeProviderCA(path string, cert *x509.Certificate) error {
	if cert == nil || len(cert.Raw) == 0 {
		return errors.New("provider certificate is missing")
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return os.WriteFile(path, block, 0o600)
}

type configFile struct {
	Server    any `json:"server"`
	KMS       any `json:"kms"`
	Providers any `json:"providers"`
	Auth      any `json:"auth"`
	RateLimit any `json:"rate_limit"`
	Quota     any `json:"quota"`
	Egress    any `json:"egress"`
}

func configDocument(port int, providerURL, keyStore, revocationPath string, minimumVersion int, candidate bool) configFile {
	server := map[string]any{
		"address": "127.0.0.1:" + fmt.Sprint(port), "read_timeout": "5s", "write_timeout": "10s",
		"shutdown_timeout": "3s", "max_request_body_size": 1 << 20,
		"tls": map[string]any{"enabled": false, "cert_file": "", "key_file": "", "ca_file": "", "min_version": "1.3"},
	}
	local := map[string]any{"master_key_env": drillMasterKeyEnv, "key_store_path": keyStore}
	auth := map[string]any{"jwt_signing_key_env": drillJWTKeyEnv, "token_expiry": "1h", "issuer": "aegis"}
	if candidate {
		local["minimum_envelope_version"] = minimumVersion
		auth["revocation"] = map[string]any{"backend": "file", "file_path": revocationPath, "refresh_interval": "100ms"}
	}
	return configFile{
		Server: server,
		KMS:    map[string]any{"mode": "local", "local": local},
		Providers: []map[string]any{{
			"id": drillProviderID, "name": "Rollback Drill Provider", "type": "openai", "base_url": providerURL,
			"api_key_id": drillProviderKeyID, "models": []string{drillModel}, "weight": 1,
			"max_rpm": 0, "max_tpm": 0, "enabled": true, "priority": 1,
		}},
		Auth:      auth,
		RateLimit: map[string]any{"enabled": true, "backend": "memory", "default_rpm": 60, "default_tpm": 0, "default_max_concurrency": 10},
		Quota:     map[string]any{"enabled": false},
		Egress:    map[string]any{"allowed_domains": []string{strings.TrimPrefix(providerURL, "https://")}},
	}
}

func writeConfig(path string, document configFile) error {
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func drillEnvironment(secrets *drillSecrets, caPath, childTemp string) []string {
	return []string{
		"HOME=/nonexistent",
		"LANG=C",
		"PATH=/usr/bin:/bin",
		"TMPDIR=" + childTemp,
		"TZ=UTC",
		drillMasterKeyEnv + "=" + hex.EncodeToString(secrets.master),
		drillJWTKeyEnv + "=" + base64.RawURLEncoding.EncodeToString(secrets.jwt),
		"SSL_CERT_FILE=" + caPath,
	}
}

func requireMigrationReport(ctx context.Context, binary *sealedExecutable, config string, env []string, dryRun bool, want string) error {
	args := []string{"operator", "kms", "migrate", "--config", config}
	if dryRun {
		args = append(args, "--dry-run")
	}
	stdout, stderr, err := runChildOutput(ctx, binary, env, args...)
	if err != nil || stdout != "" || !strings.Contains(stderr, "kms_migration "+want+" dry_run=true") {
		return errors.New("migration report mismatch")
	}
	return nil
}

func requireMigrationApply(ctx context.Context, binary *sealedExecutable, config, backup string, env []string) error {
	stdout, stderr, err := runChildOutput(ctx, binary, env, "operator", "kms", "migrate", "--config", config, "--apply", "--backup-dir", backup)
	if err != nil || stdout != "" || !strings.Contains(stderr, "kms_migration total=1 legacy=1 v2=0 migrated=1 dry_run=false") {
		return errors.New("migration apply report mismatch")
	}
	return nil
}

func runChild(ctx context.Context, binary *sealedExecutable, env []string, args ...string) error {
	_, _, err := runChildOutput(ctx, binary, env, args...)
	return err
}

func runChildOutput(ctx context.Context, binary *sealedExecutable, env []string, args ...string) (string, string, error) {
	return runBoundedProcess(ctx, 15*time.Second, binary, env, args...)
}

func runBoundedProcess(ctx context.Context, timeout time.Duration, binary *sealedExecutable, env []string, args ...string) (string, string, error) {
	if binary == nil || binary.file == nil {
		return "", "", errors.New("sealed executable is required")
	}
	cmd, err := commandForSealedExecutable(binary.file, args...)
	if err != nil {
		return "", "", err
	}
	return runBoundedCommand(ctx, timeout, cmd, env)
}

func runBoundedCommand(ctx context.Context, timeout time.Duration, cmd *exec.Cmd, env []string) (string, string, error) {
	return runBoundedCommandWithOutputLimit(ctx, timeout, cmd, env, maxChildOutputBytes)
}

func runBoundedCommandWithOutputLimit(ctx context.Context, timeout time.Duration, cmd *exec.Cmd, env []string, outputLimit int) (string, string, error) {
	if outputLimit < 1 {
		return "", "", errors.New("bounded command output limit must be positive")
	}
	processCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := processCtx.Err(); err != nil {
		return "", "", err
	}
	cmd.Env = env
	// SECURITY LIMIT: a hostile descendant can call setpgid(2) or setsid(2) and
	// escape this process group. Closing that residual requires a delegated
	// cgroup, PID namespace, or dedicated subreaper supervisor; none is assumed.
	cmd.SysProcAttr = childProcessAttributes()
	stdout := cappedBuffer{limit: outputLimit}
	stderr := cappedBuffer{limit: outputLimit}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return "", "", err
	}
	// Own the complete process group immediately after Start succeeds. Explicit
	// cancellation below kills before Wait; this defer is the final sweep on
	// every other return or future control-flow change.
	defer func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }()
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	select {
	case err := <-wait:
		// The direct child may exit after forking another process into the same
		// group. Always destroy the now-unused group before returning.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if stdout.overflow || stderr.overflow {
			return stdout.String(), stderr.String(), errors.New("child process output exceeded limit")
		}
		return stdout.String(), stderr.String(), err
	case <-processCtx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-wait
		return stdout.String(), stderr.String(), processCtx.Err()
	}
}

func snapshotEncryptedDirectory(dir string) (map[string]string, error) {
	directory, err := openOwnerOnlyDirectory(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	entries, err := readEncryptedDirectoryEntries(directory)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(entries))
	var aggregateBytes int64
	for _, entry := range entries {
		if !encryptedKeyFilename.MatchString(entry.Name()) {
			return nil, errors.New("encrypted backup entry has an invalid filename or type")
		}
		data, err := readOwnerOnlyFileAt(directory, entry.Name(), maxDrillFileBytes)
		if err != nil {
			return nil, err
		}
		aggregateBytes += int64(len(data))
		if aggregateBytes > maxEncryptedBackupAggregateBytes {
			utils.MemZero(data)
			return nil, errors.New("encrypted backup aggregate size exceeds limit")
		}
		digest := sha256.Sum256(data)
		utils.MemZero(data)
		result[entry.Name()] = hex.EncodeToString(digest[:])
	}
	return result, nil
}

func equalSnapshots(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for name, digest := range left {
		if right[name] != digest {
			return false
		}
	}
	return true
}

func restoreEncryptedBackup(backup, destination string, recorded map[string]string) error {
	directory, err := openOwnerOnlyDirectory(backup)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	entries, err := readEncryptedDirectoryEntries(directory)
	if err != nil {
		return err
	}
	if len(entries) != len(recorded) {
		return errors.New("backup entries do not match recorded snapshot")
	}
	for _, entry := range entries {
		if !encryptedKeyFilename.MatchString(entry.Name()) {
			return errors.New("backup contains an invalid entry")
		}
		if _, exists := recorded[entry.Name()]; !exists {
			return errors.New("backup entry was not recorded")
		}
	}
	contents := make(map[string][]byte, len(entries))
	defer func() {
		for _, data := range contents {
			utils.MemZero(data)
		}
	}()
	var aggregateBytes int64
	for _, entry := range entries {
		data, err := readOwnerOnlyFileAt(directory, entry.Name(), maxDrillFileBytes)
		if err != nil {
			return err
		}
		aggregateBytes += int64(len(data))
		if aggregateBytes > maxEncryptedBackupAggregateBytes {
			utils.MemZero(data)
			return errors.New("encrypted backup aggregate size exceeds limit")
		}
		digest := sha256.Sum256(data)
		if !digestMatches(hex.EncodeToString(digest[:]), recorded[entry.Name()]) {
			utils.MemZero(data)
			return errors.New("backup entry digest does not match recorded snapshot")
		}
		contents[entry.Name()] = data
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return err
	}
	destinationDirectory, err := openOwnerOnlyDirectory(destination)
	if err != nil {
		return err
	}
	defer func() { _ = destinationDirectory.Close() }()
	for name, data := range contents {
		if err := writeOwnerOnlyFileAt(destinationDirectory, name, data); err != nil {
			return err
		}
	}
	return nil
}

func openOwnerOnlyDirectory(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_DIRECTORY, 0) // #nosec G304 -- the drill fixes the directory to one non-following descriptor before reading entries.
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), "drill-owner-only-directory")
	if directory == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("opening owner-only directory")
	}
	afterSecureDirectoryOpenHook()
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || !ownedByCurrentUser(info) {
		_ = directory.Close()
		return nil, errors.New("directory is not owner-only")
	}
	return directory, nil
}

func readEncryptedDirectoryEntries(directory *os.File) ([]os.DirEntry, error) {
	entries, err := directory.ReadDir(maxEncryptedBackupEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) == 0 || len(entries) > maxEncryptedBackupEntries {
		return nil, errors.New("encrypted backup entry count is outside the allowed range")
	}
	info, statErr := directory.Stat()
	if statErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || !ownedByCurrentUser(info) {
		return nil, errors.New("encrypted backup directory changed")
	}
	return entries, nil
}

func restoreOwnerOnlyFile(source, destination, recordedDigest string) error {
	data, err := readOwnerOnlyFile(source, maxDrillFileBytes)
	if err != nil {
		return err
	}
	defer utils.MemZero(data)
	digest := sha256.Sum256(data)
	if !digestMatches(hex.EncodeToString(digest[:]), recordedDigest) {
		return errors.New("owner-only file digest does not match recorded snapshot")
	}
	return writeOwnerOnlyFile(destination, data)
}

func ownerOnlyFileDigest(path string) (string, error) {
	data, err := readOwnerOnlyFile(path, maxDrillFileBytes)
	if err != nil {
		return "", err
	}
	defer utils.MemZero(data)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func readOwnerOnlyFile(path string, maxBytes int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- caller supplies a drill-owned path; flags and same-fd validation prevent link/device races.
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "drill-owner-only-input")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("opening owner-only input")
	}
	defer func() { _ = file.Close() }()
	afterSecureFileOpenHook()
	return readOwnerOnlyOpenedFile(file, maxBytes)
}

func readOwnerOnlyFileAt(directory *os.File, name string, maxBytes int64) ([]byte, error) {
	file, err := openFileAt(directory, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return readOwnerOnlyOpenedFile(file, maxBytes)
}

func readOwnerOnlyOpenedFile(file *os.File, maxBytes int64) ([]byte, error) {
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || !ownedByCurrentUser(before) || before.Size() < 1 || before.Size() > maxBytes {
		return nil, errors.New("input is not a bounded owner-only regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		utils.MemZero(data)
		return nil, err
	}
	after, statErr := file.Stat()
	if statErr != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || int64(len(data)) != before.Size() {
		utils.MemZero(data)
		return nil, errors.New("owner-only input changed while being read")
	}
	return data, nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

func writeOwnerOnlyFile(path string, data []byte) error {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- destination is beneath a drill-owned temporary directory and must be newly created.
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "drill-owner-only-output")
	if file == nil {
		_ = syscall.Close(fd)
		return errors.New("opening owner-only output")
	}
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	if syncErr := file.Sync(); writeErr == nil && syncErr != nil {
		writeErr = syncErr
	}
	if closeErr := file.Close(); writeErr == nil && closeErr != nil {
		writeErr = closeErr
	}
	return writeErr
}

func writeOwnerOnlyFileAt(directory *os.File, name string, data []byte) error {
	file, err := openFileAt(directory, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	if syncErr := file.Sync(); writeErr == nil && syncErr != nil {
		writeErr = syncErr
	}
	if closeErr := file.Close(); writeErr == nil && closeErr != nil {
		writeErr = closeErr
	}
	return writeErr
}

func unusedLoopbackPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

type gatewayProcess struct {
	cmd     *exec.Cmd
	done    chan struct{}
	waitMu  sync.Mutex
	waitErr error
	stdout  cappedBuffer
	stderr  cappedBuffer
	once    sync.Once
	stopErr error
}

func (p *gatewayProcess) safeUpstreamFailureCode() string {
	logs := p.stdout.String() + "\n" + p.stderr.String()
	switch {
	case strings.Contains(logs, "x509") || strings.Contains(logs, "certificate"):
		return "provider_tls_verification_failed"
	case strings.Contains(logs, "egress") || strings.Contains(logs, "allowlist"):
		return "provider_egress_validation_failed"
	default:
		return "gateway_upstream_failed"
	}
}

func startGateway(binary *sealedExecutable, config string, env []string) (*gatewayProcess, error) {
	process := &gatewayProcess{done: make(chan struct{})}
	cmd, err := commandForSealedExecutable(binary.file, "--config", config)
	if err != nil {
		return nil, err
	}
	process.cmd = cmd
	process.cmd.Env = env
	process.cmd.Stdout = &process.stdout
	process.cmd.Stderr = &process.stderr
	process.cmd.SysProcAttr = childProcessAttributes()
	if err := process.cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		err := process.cmd.Wait()
		process.waitMu.Lock()
		process.waitErr = err
		process.waitMu.Unlock()
		close(process.done)
	}()
	return process, nil
}

func (p *gatewayProcess) result() error {
	p.waitMu.Lock()
	defer p.waitMu.Unlock()
	return p.waitErr
}

func (p *gatewayProcess) stop() error {
	p.once.Do(func() {
		// Always make a final best-effort sweep after the direct child exits. A
		// same-group descendant may ignore SIGTERM and outlive its parent.
		defer func() { _ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL) }()
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-p.done:
			if err := p.result(); err != nil {
				p.stopErr = err
			}
		case <-time.After(8 * time.Second):
			_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
			<-p.done
			p.stopErr = errors.New("gateway did not stop within deadline")
		}
	})
	return p.stopErr
}

func requireAuthRejections(ctx context.Context, client *http.Client, baseURL string, provider *fakeProvider) error {
	attemptsBefore := provider.attempts.Load()
	hitsBefore := provider.hits.Load()
	for _, authorization := range []string{"", "Bearer malformed"} {
		body := strings.NewReader(`{"model":"rollback-drill-model","messages":[{"role":"user","content":"release rollback drill"}],"stream":false}`)
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/chat/completions", body)
		if err != nil {
			return err
		}
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		request.Header.Del("Authorization")
		if err != nil {
			return &smokeError{code: "unauthenticated_request_transport_failed"}
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 16<<10))
		_ = response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			return &smokeError{code: "gateway_auth_negative_not_401"}
		}
		if provider.attempts.Load() != attemptsBefore || provider.hits.Load() != hitsBefore {
			return &smokeError{code: "unauthenticated_request_reached_provider"}
		}
	}
	return nil
}

func smokeGateway(ctx context.Context, process *gatewayProcess, port int, token []byte, provider *fakeProvider) error {
	baseURL := "http://127.0.0.1:" + fmt.Sprint(port)
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/health", nil)
		response, err := client.Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case <-ctx.Done():
			return &smokeError{code: "gateway_context_canceled"}
		case <-process.done:
			return &smokeError{code: "gateway_exited_before_health"}
		default:
		}
		if time.Now().After(deadline) {
			return &smokeError{code: "health_deadline_exceeded"}
		}
		time.Sleep(50 * time.Millisecond)
	}

	if err := requireAuthRejections(ctx, client, baseURL, provider); err != nil {
		return err
	}
	attemptsBefore := provider.attempts.Load()
	hitsBefore := provider.hits.Load()
	body := strings.NewReader(`{"model":"rollback-drill-model","messages":[{"role":"user","content":"release rollback drill"}],"stream":false}`)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/chat/completions", body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+string(token))
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	request.Header.Del("Authorization")
	if err != nil {
		return &smokeError{code: "authenticated_request_transport_failed"}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 16<<10))
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		switch response.StatusCode {
		case http.StatusUnauthorized:
			return &smokeError{code: "gateway_auth_rejected"}
		case http.StatusBadGateway:
			return &smokeError{code: "gateway_upstream_failed"}
		case http.StatusServiceUnavailable:
			return &smokeError{code: "gateway_service_unavailable"}
		default:
			return &smokeError{code: "authenticated_request_not_200"}
		}
	}
	if provider.attempts.Load() != attemptsBefore+1 || provider.hits.Load() != hitsBefore+1 {
		return &smokeError{code: "tls_provider_hit_mismatch"}
	}
	return nil
}

type smokeError struct{ code string }

func (e *smokeError) Error() string { return e.code }

func smokeFailureCode(err error) string {
	var smoke *smokeError
	if errors.As(err, &smoke) {
		return smoke.code
	}
	return "health_auth_kms_provider_failed"
}

func readSecretFile(path string) ([]byte, error) {
	data, err := readOwnerOnlyFile(path, maxDrillFileBytes)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	result := append([]byte(nil), trimmed...)
	utils.MemZero(data)
	if len(result) == 0 {
		return nil, errors.New("secret output is empty")
	}
	return result, nil
}

func writeSummary(output io.Writer, summary successSummary) error {
	if err := validateSuccessSummary(summary); err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(summary)
}

func validateSuccessSummary(summary successSummary) error {
	if summary.SchemaVersion != 3 || summary.Result != "PASS" ||
		(summary.EvidenceClass != evidenceFinal && summary.EvidenceClass != evidenceIterationOnly) ||
		summary.WorktreeClean != (summary.EvidenceClass == evidenceFinal) {
		return errors.New("rollback summary result identity is invalid")
	}
	if !canonicalRunID.MatchString(summary.RunID) || !fullSHA256.MatchString(summary.ContainmentNonce) ||
		summary.ContainmentNonce == strings.Repeat("0", sha256.Size*2) {
		return errors.New("rollback summary run identity is invalid")
	}
	startedAt, err := parseCanonicalUTCTimestamp(summary.StartedAt)
	if err != nil {
		return err
	}
	endedAt, err := parseCanonicalUTCTimestamp(summary.EndedAt)
	if err != nil || endedAt.Before(startedAt) {
		return errors.New("rollback summary time range is invalid")
	}
	if !fullSHA.MatchString(summary.CandidateSHA) || summary.CandidateSHA == rollbackV020SHA ||
		summary.RollbackSourceSHA != rollbackV020SHA {
		return errors.New("rollback summary source identity is invalid")
	}
	for _, digest := range []string{
		summary.RunnerBinarySHA256,
		summary.CandidateBinarySHA256,
		summary.RollbackBinarySHA256,
		summary.InputLockDigest,
	} {
		if !fullSHA256.MatchString(digest) {
			return errors.New("rollback summary digest is invalid")
		}
	}
	if summary.Migration != "legacy_file_store_to_v2_strict_pass" ||
		summary.CurrentSmoke != "health_auth_kms_tls_provider_200_pass" ||
		summary.Rollback != "encrypted_backup_restore_v0.2.0_health_auth_kms_tls_provider_200_pass" {
		return errors.New("rollback summary result contract is invalid")
	}
	return nil
}

func canonicalUTCTimestamp(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseCanonicalUTCTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || !strings.HasSuffix(value, "Z") || canonicalUTCTimestamp(parsed) != value {
		return time.Time{}, errors.New("rollback summary timestamp must be canonical UTC RFC3339")
	}
	return parsed, nil
}

func writeSummaryAfterCleanup(root string, output io.Writer, summary successSummary, cleanup func(string) error) error {
	if err := cleanup(root); err != nil {
		return &stageError{Stage: "cleanup", Reason: "temporary_cleanup_failed"}
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		return &stageError{Stage: "cleanup", Reason: "temporary_cleanup_failed"}
	}
	if summary.EndedAt == "" {
		summary.EndedAt = canonicalUTCTimestamp(time.Now().UTC())
	}
	return writeSummary(output, summary)
}

type cappedBuffer struct {
	data     []byte
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	limit := b.limit
	if limit <= 0 {
		limit = maxChildOutputBytes
	}
	remaining := limit - len(b.data)
	if remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		b.data = append(b.data, p[:remaining]...)
	}
	if len(p) > remaining {
		b.overflow = true
	}
	return len(p), nil
}

func (b *cappedBuffer) String() string { return string(b.data) }
