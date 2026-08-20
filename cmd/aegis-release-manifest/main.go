// Command aegis-release-manifest validates a detached release-evidence
// manifest and, optionally, an independent-human approval bound to it.
//
// SECURITY: Inputs are bounded, decoded strictly, and never echoed. The
// manifest intentionally excludes its own digest; approval validation computes
// that digest from the exact manifest bytes supplied by the operator.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxEvidenceFileBytes               int64 = 4 << 20
	maxEvidenceJSONDepth                     = 64
	maxEvidenceJSONValues                    = 100_000
	maxEvidenceJSONObjectMembers             = 4_096
	releaseVersionV021                       = "v0.2.1"
	rollbackV020SHA                          = "aece3298720d210f5dd242aebd72ac71af4b2aff"
	builtScopeAttestationJustification       = "supply-chain evidence is recorded per artifact"
	rollbackMigrationResult                  = "legacy_file_store_to_v2_strict_pass"
	rollbackCurrentSmokeResult               = "health_auth_kms_tls_provider_200_pass"
	rollbackRestoreResult                    = "encrypted_backup_restore_v0.2.0_health_auth_kms_tls_provider_200_pass"
	rollbackFinalEvidenceClass               = "FINAL_CANDIDATE"
)

var (
	commitPattern      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	rawSHA256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	canonicalRunID     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	requiredFinalGates = []string{
		"git-diff-check",
		"go-test",
		"go-test-race",
		"go-vet",
		"lint",
		"gosec",
		"govulncheck-source",
		"govulncheck-binary",
		"release-preflight",
		"ceo-docker-smoke",
		"rollback-drill",
		"security-review",
		"runtime-architecture-review",
		"quality-review",
		"github-actions",
		"independent-qa",
	}
	requiredReviewerRoles = []string{
		"technical-security",
		"runtime-architecture",
		"quality-release",
	}
	reviewerGateByRole = map[string]string{
		"technical-security":   "security-review",
		"runtime-architecture": "runtime-architecture-review",
		"quality-release":      "quality-review",
	}
)

type Manifest struct {
	SchemaVersion         string                `json:"schema_version"`
	ReleaseVersion        string                `json:"release_version"`
	CreatedAt             string                `json:"created_at"`
	CandidateSHA          string                `json:"candidate_sha"`
	CandidateTree         string                `json:"candidate_tree"`
	WorktreeClean         bool                  `json:"worktree_clean"`
	EvidenceMode          string                `json:"evidence_mode"`
	TagName               string                `json:"tag_name"`
	TagObjectSHA          string                `json:"tag_object_sha"`
	TagTargetSHA          string                `json:"tag_target_sha"`
	ArtifactScope         ArtifactScope         `json:"artifact_scope"`
	Artifacts             []Artifact            `json:"artifacts"`
	Gates                 []Gate                `json:"gates"`
	QA                    QA                    `json:"qa"`
	ContainerSmoke        *ContainerSmoke       `json:"container_smoke,omitempty"`
	Reviewers             []Reviewer            `json:"reviewers"`
	ReleaseApprovalPolicy ReleaseApprovalPolicy `json:"release_approval_policy"`
	Rollback              RollbackEvidence      `json:"rollback"`
	AcceptedRisks         []Finding             `json:"accepted_risks"`
	OpenFindings          []Finding             `json:"open_findings"`
	UnverifiedSurfaces    []string              `json:"unverified_surfaces"`
	ManifestID            string                `json:"manifest_id"`
	RetentionPolicy       string                `json:"retention_policy"`
}

type ArtifactScope struct {
	Decision   string      `json:"decision"`
	Rationale  string      `json:"rationale"`
	SBOM       Attestation `json:"sbom"`
	Signature  Attestation `json:"signature"`
	Provenance Attestation `json:"provenance"`
}

type Artifact struct {
	Type        string      `json:"type"`
	Platform    string      `json:"platform"`
	Reference   string      `json:"reference"`
	Digest      string      `json:"digest"`
	SourceSHA   string      `json:"source_sha"`
	EmbeddedSHA string      `json:"embedded_source_sha"`
	Toolchain   string      `json:"toolchain"`
	SBOM        Attestation `json:"sbom"`
	Signature   Attestation `json:"signature"`
	Provenance  Attestation `json:"provenance"`
}

type Attestation struct {
	Status        string `json:"status"`
	Reference     string `json:"reference,omitempty"`
	Digest        string `json:"digest,omitempty"`
	Justification string `json:"justification,omitempty"`
}

type Gate struct {
	Name                  string   `json:"name"`
	Status                string   `json:"status"`
	Timestamp             string   `json:"timestamp"`
	ToolVersion           string   `json:"tool_version"`
	RunURL                string   `json:"run_url,omitempty"`
	RunID                 string   `json:"run_id"`
	EvidenceRef           string   `json:"evidence_ref"`
	EvidenceDigest        string   `json:"evidence_digest"`
	CandidateSHA          string   `json:"candidate_sha"`
	ArtifactDigests       []string `json:"artifact_digests"`
	AttestationReferences []string `json:"attestation_references,omitempty"`
	AttestationDigests    []string `json:"attestation_digests,omitempty"`
}

type QA struct {
	Repository           string   `json:"repository"`
	Revision             string   `json:"revision"`
	SUTSHA               string   `json:"sut_sha"`
	SUTBinaryDigest      string   `json:"sut_binary_digest"`
	SUTDigests           []string `json:"sut_digests"`
	RunURL               string   `json:"run_url"`
	RunID                string   `json:"run_id"`
	EvidenceRef          string   `json:"evidence_ref"`
	EvidenceBundleDigest string   `json:"evidence_bundle_digest"`
}

type ContainerSmoke struct {
	ArtifactBinding  string `json:"artifact_binding"`
	Timestamp        string `json:"timestamp"`
	RunURL           string `json:"run_url"`
	RunID            string `json:"run_id"`
	EvidenceRef      string `json:"evidence_ref"`
	EvidenceDigest   string `json:"evidence_digest"`
	ImageID          string `json:"image_id"`
	ImageDigest      string `json:"image_digest"`
	SourceSHA        string `json:"source_sha"`
	OS               string `json:"os"`
	Architecture     string `json:"architecture"`
	RuntimeUser      string `json:"runtime_user"`
	ReadOnlyRoot     bool   `json:"read_only_root"`
	HealthStatus     string `json:"health_status"`
	AuthStatus       string `json:"auth_status"`
	RevocationStatus string `json:"revocation_status"`
	CleanupStatus    string `json:"cleanup_status"`
}

type Reviewer struct {
	Identity       string `json:"identity"`
	Role           string `json:"role"`
	Decision       string `json:"decision"`
	Timestamp      string `json:"timestamp"`
	GateName       string `json:"gate_name"`
	RunURL         string `json:"run_url"`
	RunID          string `json:"run_id"`
	EvidenceRef    string `json:"evidence_ref"`
	EvidenceDigest string `json:"evidence_digest"`
}

type ReleaseApprovalPolicy struct {
	RequiredRole      string `json:"required_role"`
	RequiredKeyID     string `json:"required_key_id"`
	MinimumApprovals  int    `json:"minimum_approvals"`
	MustBeIndependent bool   `json:"must_be_independent"`
	DetachedApproval  bool   `json:"detached_approval"`
	TrustPolicyURI    string `json:"trust_policy_uri"`
	TrustPolicyDigest string `json:"trust_policy_digest"`
	VerifierURI       string `json:"verifier_uri"`
	VerifierDigest    string `json:"verifier_digest"`
}

type RollbackEvidence struct {
	Status                    string `json:"status"`
	Timestamp                 string `json:"timestamp"`
	RunID                     string `json:"run_id"`
	ContainmentNonce          string `json:"containment_nonce"`
	StartedAt                 string `json:"started_at"`
	EndedAt                   string `json:"ended_at"`
	RunnerBinarySHA256        string `json:"runner_binary_sha256"`
	EvidenceRef               string `json:"evidence_ref"`
	EvidenceDigest            string `json:"evidence_digest"`
	InputLockRef              string `json:"input_lock_ref"`
	InputLockDigest           string `json:"input_lock_digest"`
	ContainmentProfile        string `json:"containment_profile"`
	ContainmentEvidenceRef    string `json:"containment_evidence_ref"`
	ContainmentEvidenceDigest string `json:"containment_evidence_digest"`
	CandidateSHA              string `json:"candidate_sha"`
	CandidateBinaryDigest     string `json:"candidate_binary_digest"`
	OldTag                    string `json:"old_tag"`
	OldTagSHA                 string `json:"old_tag_sha"`
	OldBinaryDigest           string `json:"old_binary_digest"`
}

// rollbackReportBinding mirrors the exact successful JSON emitted by
// cmd/aegis-rollback-drill. Its digest prevents report/manifest identity
// splicing; it does not establish external containment, storage, trust, or
// authorization for the report.
type rollbackReportBinding struct {
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

type Finding struct {
	ID             string `json:"id"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Mitigation     string `json:"mitigation"`
	EvidenceRef    string `json:"evidence_ref"`
	EvidenceDigest string `json:"evidence_digest"`
	Accepted       bool   `json:"accepted"`
	AcceptedBy     string `json:"accepted_by"`
	AcceptedAt     string `json:"accepted_at"`
	Owner          string `json:"owner"`
	Deadline       string `json:"deadline"`
}

type Approval struct {
	SchemaVersion    string   `json:"schema_version"`
	ApproverIdentity string   `json:"approver_identity"`
	ApproverRole     string   `json:"approver_role"`
	ApproverKeyID    string   `json:"approver_key_id"`
	Decision         string   `json:"decision"`
	Timestamp        string   `json:"timestamp"`
	ManifestDigest   string   `json:"manifest_digest"`
	CandidateSHA     string   `json:"candidate_sha"`
	ArtifactDigests  []string `json:"artifact_digests"`
}

type ReleaseClosure struct {
	SchemaVersion      string            `json:"schema_version"`
	ReleaseVersion     string            `json:"release_version"`
	CreatedAt          string            `json:"created_at"`
	ManifestURI        string            `json:"manifest_uri"`
	ManifestDigest     string            `json:"manifest_digest"`
	ApprovalRef        string            `json:"approval_ref"`
	ApprovalDigest     string            `json:"approval_digest"`
	TrustPolicyURI     string            `json:"trust_policy_uri"`
	TrustPolicyDigest  string            `json:"trust_policy_digest"`
	VerifierURI        string            `json:"verifier_uri"`
	VerifierDigest     string            `json:"verifier_digest"`
	CandidateSHA       string            `json:"candidate_sha"`
	TagName            string            `json:"tag_name"`
	TagObjectSHA       string            `json:"tag_object_sha"`
	TagTargetSHA       string            `json:"tag_target_sha"`
	ArtifactScope      string            `json:"artifact_scope"`
	ArtifactDigests    []string          `json:"artifact_digests"`
	RemoteVerification ClosureCheck      `json:"remote_verification"`
	PublishedSmoke     ClosureCheck      `json:"published_smoke"`
	Monitoring         ClosureMonitoring `json:"monitoring"`
	Outcome            string            `json:"outcome"`
	OutcomeReason      string            `json:"outcome_reason"`
	Rollback           *ClosureCheck     `json:"rollback,omitempty"`
}

type ClosureCheck struct {
	Status         string `json:"status"`
	EvidenceRef    string `json:"evidence_ref,omitempty"`
	EvidenceDigest string `json:"evidence_digest,omitempty"`
	Justification  string `json:"justification,omitempty"`
}

type ClosureMonitoring struct {
	StartedAt      string `json:"started_at"`
	EndedAt        string `json:"ended_at"`
	Status         string `json:"status"`
	EvidenceRef    string `json:"evidence_ref"`
	EvidenceDigest string `json:"evidence_digest"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("aegis-release-manifest", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "path to the final external manifest")
	closurePath := flags.String("closure", "", "path to a detached post-publication closure record")
	approvalPath := flags.String("approval", "", "path to detached human approval")
	signaturePath := flags.String("approval-signature", "", "path to detached Ed25519 signature over approval bytes")
	publicKeyPath := flags.String("approver-public-key", "", "path to trusted hex Ed25519 public key")
	expectedIdentity := flags.String("expected-approver-identity", "", "trusted independent approver identity")
	expectedRole := flags.String("expected-approver-role", "", "trusted independent approver role")
	expectedKeyID := flags.String("expected-approver-key-id", "", "trusted independent approver key ID")
	schemaOnly := flags.Bool("schema-only", false, "validate manifest structure without claiming release approval")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *manifestPath == "" || flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "usage: aegis-release-manifest -manifest PATH [-closure PATH] (-schema-only | -approval PATH -approval-signature PATH -approver-public-key PATH -expected-approver-identity ID -expected-approver-role ROLE -expected-approver-key-id KEY_ID)")
		return 2
	}
	approvalInputs := []string{*approvalPath, *signaturePath, *publicKeyPath, *expectedIdentity, *expectedRole, *expectedKeyID}
	providedApprovalInputs := 0
	for _, value := range approvalInputs {
		if value != "" {
			providedApprovalInputs++
		}
	}
	if (*schemaOnly && providedApprovalInputs != 0) || (!*schemaOnly && providedApprovalInputs != len(approvalInputs)) {
		_, _ = fmt.Fprintln(stderr, "release evidence validation failed: choose schema-only or provide every trusted approval input")
		return 2
	}
	if *closurePath != "" && !*schemaOnly {
		_, _ = fmt.Fprintln(stderr, "release evidence validation failed: closure validation is schema-only and cannot authorize release")
		return 2
	}

	rawManifest, err := readBoundedRegularFile(*manifestPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "release evidence validation failed: reading manifest")
		return 1
	}
	manifest, err := decodeManifest(rawManifest)
	if err == nil {
		err = validateManifest(&manifest)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "release evidence validation failed: %v\n", err)
		return 1
	}

	digest := sha256.Sum256(rawManifest)
	if *schemaOnly {
		if *closurePath != "" {
			rawClosure, readErr := readBoundedRegularFile(*closurePath)
			if readErr != nil {
				_, _ = fmt.Fprintln(stderr, "release evidence validation failed: reading closure")
				return 1
			}
			closure, decodeErr := decodeClosure(rawClosure)
			if decodeErr == nil {
				decodeErr = validateClosure(rawManifest, &manifest, &closure)
			}
			if decodeErr != nil {
				_, _ = fmt.Fprintf(stderr, "release evidence validation failed: %v\n", decodeErr)
				return 1
			}
			_, _ = fmt.Fprintf(stdout, "CLOSURE_SCHEMA_VALID_NOT_RELEASE_APPROVED manifest_digest=sha256:%s candidate_sha=%s outcome=%s\n",
				hex.EncodeToString(digest[:]), manifest.CandidateSHA, closure.Outcome)
			return 0
		}
		_, _ = fmt.Fprintf(stdout, "SCHEMA_VALID_NOT_RELEASE_APPROVED manifest_digest=sha256:%s candidate_sha=%s artifact_count=%d\n",
			hex.EncodeToString(digest[:]), manifest.CandidateSHA, len(manifest.Artifacts))
		return 0
	}

	rawApproval, readErr := readBoundedRegularFile(*approvalPath)
	if readErr != nil {
		_, _ = fmt.Fprintln(stderr, "release evidence validation failed: reading approval")
		return 1
	}
	rawSignature, signatureErr := readBoundedRegularFile(*signaturePath)
	rawPublicKey, publicKeyErr := readBoundedRegularFile(*publicKeyPath)
	if signatureErr != nil || publicKeyErr != nil {
		_, _ = fmt.Fprintln(stderr, "release evidence validation failed: reading trusted approval signature material")
		return 1
	}
	approval, approvalErr := decodeApproval(rawApproval)
	if approvalErr == nil {
		approvalErr = validateApproval(rawManifest, &manifest, &approval)
	}
	if approvalErr == nil && (approval.ApproverIdentity != *expectedIdentity || approval.ApproverRole != *expectedRole ||
		approval.ApproverKeyID != *expectedKeyID || manifest.ReleaseApprovalPolicy.RequiredRole != *expectedRole ||
		manifest.ReleaseApprovalPolicy.RequiredKeyID != *expectedKeyID) {
		approvalErr = errors.New("approval identity, role, or key ID does not match trusted expectations")
	}
	if approvalErr == nil {
		approvalErr = validateApprovalSignature(rawApproval, string(rawPublicKey), string(rawSignature), *expectedKeyID)
	}
	if approvalErr != nil {
		_, _ = fmt.Fprintf(stderr, "release evidence validation failed: %v\n", approvalErr)
		return 1
	}

	// The caller supplied the signer key and every claimed identity in this
	// invocation. That proves byte-level binding, but it cannot establish that
	// the signer is an independently governed trusted approver. Fail closed
	// until an external trust policy outside the release owner's control exists.
	_, _ = fmt.Fprintln(stderr, "release evidence validation blocked: approval binding is cryptographically valid, but no independently administered trust anchor is configured")
	return 1
}

func readBoundedRegularFile(path string) ([]byte, error) {
	file, err := openEvidenceFile(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 ||
		before.Size() < 1 || before.Size() > maxEvidenceFileBytes {
		return nil, errors.New("evidence input must be a bounded non-writable regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxEvidenceFileBytes+1))
	if err != nil || int64(len(raw)) > maxEvidenceFileBytes {
		return nil, errors.New("evidence input exceeds size limit")
	}
	after, statErr := file.Stat()
	if statErr != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) ||
		int64(len(raw)) != before.Size() {
		return nil, errors.New("evidence input changed while being read")
	}
	return raw, nil
}

func decodeManifest(raw []byte) (Manifest, error) {
	return decodeStrict[Manifest](raw, "manifest")
}

func decodeApproval(raw []byte) (Approval, error) {
	return decodeStrict[Approval](raw, "approval")
}

func decodeClosure(raw []byte) (ReleaseClosure, error) {
	return decodeStrict[ReleaseClosure](raw, "closure")
}

func decodeStrict[T any](raw []byte, name string) (T, error) {
	var zero T
	if len(raw) == 0 || int64(len(raw)) > maxEvidenceFileBytes || !utf8.Valid(raw) {
		return zero, fmt.Errorf("invalid %s JSON", name)
	}
	if err := rejectDuplicateMembersForType[T](raw); err != nil {
		return zero, fmt.Errorf("invalid %s JSON", name)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		return zero, fmt.Errorf("invalid %s JSON", name)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return zero, fmt.Errorf("invalid %s JSON", name)
	}
	return value, nil
}

func rejectDuplicateMembers(raw []byte) error {
	return rejectDuplicateMembersForExpectedType(raw, nil)
}

func rejectDuplicateMembersForType[T any](raw []byte) error {
	var value T
	return rejectDuplicateMembersForExpectedType(raw, reflect.TypeOf(value))
}

func rejectDuplicateMembersForExpectedType(raw []byte, expected reflect.Type) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	values := 0
	if err := consumeUniqueJSONValue(decoder, expected, 0, &values); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func consumeUniqueJSONValue(decoder *json.Decoder, expected reflect.Type, depth int, values *int) error {
	if depth > maxEvidenceJSONDepth {
		return errors.New("JSON nesting exceeds limit")
	}
	*values++
	if *values > maxEvidenceJSONValues {
		return errors.New("JSON value count exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		if text, isString := token.(string); isString && strings.ContainsRune(text, utf8.RuneError) {
			return errors.New("JSON string contains an invalid Unicode scalar")
		}
		return nil
	}
	switch delim {
	case '{':
		expectedMembers := exactJSONMemberTypes(expected)
		seen := make(map[string]struct{})
		seenFolded := make(map[string]struct{})
		members := 0
		for decoder.More() {
			members++
			if members > maxEvidenceJSONObjectMembers {
				return errors.New("JSON object member count exceeds limit")
			}
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object member is not a string")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate object member")
			}
			folded, ok := foldEvidenceMemberName(key)
			if !ok {
				return errors.New("non-ASCII object member")
			}
			if _, exists := seenFolded[folded]; exists {
				return errors.New("case-folded object member collision")
			}
			memberType := reflect.Type(nil)
			if expectedMembers != nil {
				var exists bool
				memberType, exists = expectedMembers[key]
				if !exists {
					return errors.New("unknown or case-mismatched object member")
				}
			}
			seen[key] = struct{}{}
			seenFolded[folded] = struct{}{}
			if err := consumeUniqueJSONValue(decoder, memberType, depth+1, values); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unterminated object")
		}
	case '[':
		elementType := jsonElementType(expected)
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder, elementType, depth+1, values); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("unterminated array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func exactJSONMemberTypes(expected reflect.Type) map[string]reflect.Type {
	expected = indirectType(expected)
	if expected == nil || expected.Kind() != reflect.Struct {
		return nil
	}
	members := make(map[string]reflect.Type, expected.NumField())
	for index := range expected.NumField() {
		field := expected.Field(index)
		if field.PkgPath != "" {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		members[name] = field.Type
	}
	return members
}

func jsonElementType(expected reflect.Type) reflect.Type {
	expected = indirectType(expected)
	if expected != nil && (expected.Kind() == reflect.Array || expected.Kind() == reflect.Slice) {
		return expected.Elem()
	}
	return nil
}

func indirectType(value reflect.Type) reflect.Type {
	for value != nil && value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	return value
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func validateManifest(manifest *Manifest) error {
	if manifest.SchemaVersion != "aegis.release-evidence/v1" {
		return errors.New("unsupported schema_version")
	}
	if manifest.ReleaseVersion != releaseVersionV021 || manifest.TagName != releaseVersionV021 {
		return errors.New("release_version and tag_name must equal v0.2.1")
	}
	createdAt, err := parseTimestamp(manifest.CreatedAt, "created_at")
	if err != nil {
		return err
	}
	for field, value := range map[string]string{
		"candidate_sha":  manifest.CandidateSHA,
		"candidate_tree": manifest.CandidateTree,
		"tag_object_sha": manifest.TagObjectSHA,
		"tag_target_sha": manifest.TagTargetSHA,
	} {
		if !commitPattern.MatchString(value) {
			return fmt.Errorf("%s must be a full lowercase Git object SHA", field)
		}
	}
	if manifest.TagTargetSHA != manifest.CandidateSHA {
		return errors.New("tag_target_sha must equal candidate_sha")
	}
	if manifest.TagObjectSHA == manifest.TagTargetSHA {
		return errors.New("v0.2.1 requires an annotated tag object distinct from tag_target_sha")
	}
	if !manifest.WorktreeClean || manifest.EvidenceMode != "FINAL" {
		return errors.New("final evidence requires a clean worktree and FINAL evidence_mode")
	}

	artifactDigests := make(map[string]struct{}, len(manifest.Artifacts))
	if err := validateArtifactScope(manifest, artifactDigests); err != nil {
		return err
	}
	if len(manifest.Gates) == 0 {
		return errors.New("gates must not be empty")
	}
	seenGates := make(map[string]struct{}, len(manifest.Gates))
	gatesByName := make(map[string]Gate, len(manifest.Gates))
	for index, gate := range manifest.Gates {
		if gate.Name == "" || gate.Status != "PASS" || gate.ToolVersion == "" || gate.RunID == "" ||
			!validHTTPSURI(gate.RunURL) || !validHTTPSURI(gate.EvidenceRef) ||
			!digestPattern.MatchString(gate.EvidenceDigest) {
			return fmt.Errorf("gates[%d] is incomplete or not PASS", index)
		}
		if _, exists := seenGates[gate.Name]; exists {
			return errors.New("gates contains duplicate names")
		}
		seenGates[gate.Name] = struct{}{}
		gatesByName[gate.Name] = gate
		gateTime, err := parseTimestamp(gate.Timestamp, "gate timestamp")
		if err != nil {
			return err
		}
		if gateTime.After(createdAt) {
			return errors.New("gate timestamp must not be after manifest created_at")
		}
		if gate.CandidateSHA != manifest.CandidateSHA {
			return errors.New("every gate candidate_sha must equal candidate_sha")
		}
		seenArtifactDigests := make(map[string]struct{}, len(gate.ArtifactDigests))
		for _, digest := range gate.ArtifactDigests {
			if _, exists := artifactDigests[digest]; !exists {
				return errors.New("gate artifact_digests contains an unpublished digest")
			}
			if _, duplicate := seenArtifactDigests[digest]; duplicate {
				return errors.New("gate artifact_digests contains a duplicate")
			}
			seenArtifactDigests[digest] = struct{}{}
		}
	}
	for _, required := range requiredFinalGates {
		if _, exists := seenGates[required]; !exists {
			return fmt.Errorf("required final gate %q is missing", required)
		}
	}
	if err := validateBuiltArtifactBindings(manifest, gatesByName); err != nil {
		return err
	}
	if err := validateQA(manifest, artifactDigests); err != nil {
		return err
	}
	if err := validateContainerSmoke(manifest.ContainerSmoke, manifest.CandidateSHA, manifest.ArtifactScope.Decision, manifest.Artifacts); err != nil {
		return err
	}
	if err := validateReviewers(manifest.Reviewers, createdAt, gatesByName); err != nil {
		return err
	}
	policy := manifest.ReleaseApprovalPolicy
	if policy.RequiredRole == "" || !digestPattern.MatchString(policy.RequiredKeyID) || policy.MinimumApprovals != 1 ||
		!policy.MustBeIndependent || !policy.DetachedApproval || !validHTTPSURI(policy.TrustPolicyURI) ||
		!digestPattern.MatchString(policy.TrustPolicyDigest) || !validHTTPSURI(policy.VerifierURI) ||
		!digestPattern.MatchString(policy.VerifierDigest) {
		return errors.New("release_approval_policy must require detached independent-human approval")
	}
	if err := validateRollback(manifest.Rollback, manifest.CandidateSHA, manifest.WorktreeClean, manifest.EvidenceMode, createdAt); err != nil {
		return err
	}
	if err := validateGateEvidenceBindings(gatesByName, manifest.QA, manifest.Rollback, manifest.ContainerSmoke); err != nil {
		return err
	}
	if err := validateFindings(manifest.AcceptedRisks, true, createdAt); err != nil {
		return fmt.Errorf("accepted_risks: %w", err)
	}
	if len(manifest.OpenFindings) != 0 {
		return errors.New("final evidence requires open_findings to be empty")
	}
	if len(manifest.UnverifiedSurfaces) != 0 {
		return errors.New("final evidence requires unverified_surfaces to be empty")
	}
	if strings.TrimSpace(manifest.ManifestID) == "" || strings.TrimSpace(manifest.RetentionPolicy) == "" {
		return errors.New("manifest_id and retention_policy are required")
	}
	return nil
}

func validateArtifactScope(manifest *Manifest, digests map[string]struct{}) error {
	scope := manifest.ArtifactScope
	if strings.TrimSpace(scope.Rationale) == "" {
		return errors.New("artifact_scope rationale is required")
	}
	switch scope.Decision {
	case "source_tag_only":
		if len(manifest.Artifacts) != 0 {
			return errors.New("source_tag_only scope requires an empty artifacts list")
		}
		for _, item := range []Attestation{scope.SBOM, scope.Signature, scope.Provenance} {
			if err := validateAttestation(item); err != nil || item.Status != "not_applicable" {
				return errors.New("source_tag_only scope requires justified not_applicable supply-chain statuses")
			}
		}
	case "binaries", "container_images", "binaries_and_container_images":
		if len(manifest.Artifacts) == 0 {
			return errors.New("built-artifact scope requires artifacts")
		}
		canonical := Attestation{
			Status:        "not_applicable",
			Justification: builtScopeAttestationJustification,
		}
		for _, item := range []Attestation{scope.SBOM, scope.Signature, scope.Provenance} {
			if item != canonical {
				return errors.New("built-artifact scope requires canonical per-artifact supply-chain summary")
			}
		}
	default:
		return errors.New("unsupported artifact_scope decision")
	}

	hasBinary, hasContainer := false, false
	for index, artifact := range manifest.Artifacts {
		if err := validateArtifact(artifact, manifest.CandidateSHA); err != nil {
			return fmt.Errorf("artifacts[%d]: %w", index, err)
		}
		if _, duplicate := digests[artifact.Digest]; duplicate {
			return errors.New("artifacts contains duplicate digests")
		}
		digests[artifact.Digest] = struct{}{}
		hasBinary = hasBinary || artifact.Type == "binary"
		hasContainer = hasContainer || artifact.Type == "container"
	}
	if scope.Decision == "binaries" && (!hasBinary || hasContainer) {
		return errors.New("binaries scope must contain only binaries")
	}
	if scope.Decision == "container_images" && (!hasContainer || hasBinary) {
		return errors.New("container_images scope must contain only containers")
	}
	if scope.Decision == "binaries_and_container_images" && (!hasBinary || !hasContainer) {
		return errors.New("combined scope requires both binary and container artifacts")
	}
	return nil
}

func validateArtifact(artifact Artifact, candidateSHA string) error {
	if artifact.Type != "binary" && artifact.Type != "container" {
		return errors.New("unsupported artifact type")
	}
	if artifact.Platform == "" || !validImmutableArtifactURI(artifact.Reference) || artifact.Toolchain == "" {
		return errors.New("platform, immutable reference, and toolchain are required")
	}
	if !digestPattern.MatchString(artifact.Digest) {
		return errors.New("digest must be sha256")
	}
	if artifact.SourceSHA != candidateSHA || artifact.EmbeddedSHA != candidateSHA {
		return errors.New("source and embedded SHA must equal candidate_sha")
	}
	for _, item := range []Attestation{artifact.SBOM, artifact.Signature, artifact.Provenance} {
		if err := validateAttestation(item); err != nil || item.Status != "present" {
			if err == nil {
				err = errors.New("built artifacts require present SBOM, signature, and provenance")
			}
			return err
		}
	}
	return nil
}

func validateAttestation(item Attestation) error {
	switch item.Status {
	case "present":
		if !validImmutableArtifactURI(item.Reference) || !digestPattern.MatchString(item.Digest) || item.Justification != "" {
			return errors.New("present attestation requires reference and sha256 digest")
		}
	case "not_applicable":
		if strings.TrimSpace(item.Justification) == "" || item.Reference != "" || item.Digest != "" {
			return errors.New("not_applicable attestation requires only a justification")
		}
	default:
		return errors.New("attestation status must be present or not_applicable")
	}
	return nil
}

func validateQA(manifest *Manifest, artifactDigests map[string]struct{}) error {
	qa := manifest.QA
	if !validHTTPSURI(qa.Repository) || !validHTTPSURI(qa.RunURL) || qa.RunID == "" ||
		!validHTTPSURI(qa.EvidenceRef) || !commitPattern.MatchString(qa.Revision) ||
		!digestPattern.MatchString(qa.SUTBinaryDigest) || !digestPattern.MatchString(qa.EvidenceBundleDigest) {
		return errors.New("qa evidence is incomplete")
	}
	if qa.SUTSHA != manifest.CandidateSHA {
		return errors.New("qa.sut_sha must equal candidate_sha")
	}
	seen := make(map[string]struct{}, len(qa.SUTDigests))
	for _, digest := range qa.SUTDigests {
		if _, exists := artifactDigests[digest]; !exists {
			return errors.New("qa.sut_digests contains an unpublished digest")
		}
		if _, duplicate := seen[digest]; duplicate {
			return errors.New("qa.sut_digests contains a duplicate")
		}
		seen[digest] = struct{}{}
	}
	if len(manifest.Artifacts) > 0 && !equalStrings(qa.SUTDigests, artifactDigestOrder(manifest.Artifacts)) {
		return errors.New("qa.sut_digests must equal the ordered published artifact digests")
	}
	var publishedBinaryDigests []string
	for _, artifact := range manifest.Artifacts {
		if artifact.Type == "binary" {
			publishedBinaryDigests = append(publishedBinaryDigests, artifact.Digest)
		}
	}
	if len(publishedBinaryDigests) > 0 && !containsString(publishedBinaryDigests, qa.SUTBinaryDigest) {
		return errors.New("qa.sut_binary_digest must name a published binary artifact")
	}
	return nil
}

func validateGateEvidenceBindings(gates map[string]Gate, qa QA, rollback RollbackEvidence, smoke *ContainerSmoke) error {
	qaGate := gates["independent-qa"]
	if qaGate.RunID != qa.RunID || qaGate.RunURL != qa.RunURL || qaGate.EvidenceRef != qa.EvidenceRef ||
		qaGate.EvidenceDigest != qa.EvidenceBundleDigest {
		return errors.New("independent-qa gate run and evidence identity must exactly match qa")
	}

	rollbackGate := gates["rollback-drill"]
	if rollbackGate.RunID != rollback.RunID || rollbackGate.EvidenceRef != rollback.EvidenceRef ||
		rollbackGate.EvidenceDigest != rollback.EvidenceDigest || rollbackGate.Timestamp != rollback.Timestamp {
		return errors.New("rollback-drill gate run, evidence, and timestamp must exactly match rollback")
	}

	containerGate := gates["ceo-docker-smoke"]
	if smoke == nil || containerGate.RunID != smoke.RunID || containerGate.RunURL != smoke.RunURL ||
		containerGate.EvidenceRef != smoke.EvidenceRef || containerGate.EvidenceDigest != smoke.EvidenceDigest ||
		containerGate.Timestamp != smoke.Timestamp {
		return errors.New("ceo-docker-smoke gate run, evidence, and timestamp must exactly match container_smoke")
	}
	return nil
}

func validateBuiltArtifactBindings(manifest *Manifest, gates map[string]Gate) error {
	if len(manifest.Artifacts) == 0 {
		for _, gate := range gates {
			if len(gate.ArtifactDigests) != 0 || len(gate.AttestationReferences) != 0 || len(gate.AttestationDigests) != 0 {
				return errors.New("source-only gates must not claim artifact or attestation evidence")
			}
		}
		return nil
	}

	var binaries, containers []string
	for _, artifact := range manifest.Artifacts {
		switch artifact.Type {
		case "binary":
			binaries = append(binaries, artifact.Digest)
		case "container":
			containers = append(containers, artifact.Digest)
		}
	}
	if len(binaries) > 0 {
		if !equalStrings(gates["govulncheck-binary"].ArtifactDigests, binaries) {
			return errors.New("govulncheck-binary must bind every published binary digest in order")
		}
		if !containsString(binaries, manifest.Rollback.CandidateBinaryDigest) {
			return errors.New("rollback candidate binary digest must name a published binary")
		}
	}
	if len(containers) > 0 && !equalStrings(gates["ceo-docker-smoke"].ArtifactDigests, containers) {
		return errors.New("ceo-docker-smoke must bind every published container digest in order")
	}
	ordered := artifactDigestOrder(manifest.Artifacts)
	if !equalStrings(gates["independent-qa"].ArtifactDigests, ordered) {
		return errors.New("independent-qa must bind every published artifact digest in order")
	}
	for _, gateName := range []string{"sbom-verify", "artifact-signature-verify", "provenance-verify"} {
		if !equalStrings(gates[gateName].ArtifactDigests, ordered) {
			return fmt.Errorf("%s must bind every published artifact digest in order", gateName)
		}
	}

	expectedReferences := map[string][]string{
		"sbom-verify":               make([]string, 0, len(manifest.Artifacts)),
		"artifact-signature-verify": make([]string, 0, len(manifest.Artifacts)),
		"provenance-verify":         make([]string, 0, len(manifest.Artifacts)),
	}
	expectedDigests := map[string][]string{
		"sbom-verify":               make([]string, 0, len(manifest.Artifacts)),
		"artifact-signature-verify": make([]string, 0, len(manifest.Artifacts)),
		"provenance-verify":         make([]string, 0, len(manifest.Artifacts)),
	}
	for _, artifact := range manifest.Artifacts {
		expectedReferences["sbom-verify"] = append(expectedReferences["sbom-verify"], artifact.SBOM.Reference)
		expectedDigests["sbom-verify"] = append(expectedDigests["sbom-verify"], artifact.SBOM.Digest)
		expectedReferences["artifact-signature-verify"] = append(expectedReferences["artifact-signature-verify"], artifact.Signature.Reference)
		expectedDigests["artifact-signature-verify"] = append(expectedDigests["artifact-signature-verify"], artifact.Signature.Digest)
		expectedReferences["provenance-verify"] = append(expectedReferences["provenance-verify"], artifact.Provenance.Reference)
		expectedDigests["provenance-verify"] = append(expectedDigests["provenance-verify"], artifact.Provenance.Digest)
	}
	for gateName, gate := range gates {
		expectedRefs, attestationGate := expectedReferences[gateName]
		if !attestationGate {
			if len(gate.AttestationReferences) != 0 || len(gate.AttestationDigests) != 0 {
				return fmt.Errorf("%s must not claim attestation evidence", gateName)
			}
			continue
		}
		if !equalStrings(gate.AttestationReferences, expectedRefs) ||
			!equalStrings(gate.AttestationDigests, expectedDigests[gateName]) {
			return fmt.Errorf("%s must bind its per-artifact attestation references and digests in order", gateName)
		}
	}
	return nil
}

func validateContainerSmoke(smoke *ContainerSmoke, candidateSHA, scope string, artifacts []Artifact) error {
	if smoke == nil {
		return errors.New("container_smoke evidence is required")
	}
	if err := requireTimestamp(smoke.Timestamp, "container_smoke timestamp"); err != nil {
		return err
	}
	if smoke.RunID == "" || !validHTTPSURI(smoke.RunURL) || !validHTTPSURI(smoke.EvidenceRef) ||
		!digestPattern.MatchString(smoke.EvidenceDigest) || !digestPattern.MatchString(smoke.ImageID) ||
		!digestPattern.MatchString(smoke.ImageDigest) || smoke.SourceSHA != candidateSHA ||
		smoke.OS == "" || smoke.Architecture == "" || smoke.RuntimeUser == "" || !smoke.ReadOnlyRoot {
		return errors.New("container_smoke identity or runtime boundary is incomplete")
	}
	for _, status := range []string{smoke.HealthStatus, smoke.AuthStatus, smoke.RevocationStatus, smoke.CleanupStatus} {
		if status != "PASS" {
			return errors.New("container_smoke checks must all PASS")
		}
	}
	if scope == "container_images" || scope == "binaries_and_container_images" {
		if smoke.ArtifactBinding != "PUBLISHED_ARTIFACT" {
			return errors.New("published container smoke must declare PUBLISHED_ARTIFACT binding")
		}
		var containerDigest string
		containerCount := 0
		for _, artifact := range artifacts {
			if artifact.Type == "container" {
				containerCount++
				containerDigest = artifact.Digest
			}
		}
		if containerCount != 1 || smoke.ImageDigest != containerDigest {
			return errors.New("single container_smoke evidence requires exactly one matching published container")
		}
	} else if smoke.ArtifactBinding != "PREPUBLICATION_CANDIDATE_NOT_PUBLISHED" {
		return errors.New("container smoke without a published container must declare PREPUBLICATION_CANDIDATE_NOT_PUBLISHED")
	}
	return nil
}

func validateReviewers(reviewers []Reviewer, createdAt time.Time, gates map[string]Gate) error {
	if len(reviewers) == 0 {
		return errors.New("reviewers must not be empty")
	}
	roles := make(map[string]struct{}, len(reviewers))
	identities := make(map[string]struct{}, len(reviewers))
	for _, reviewer := range reviewers {
		canonicalIdentity, identityOK := canonicalASCIIIdentity(reviewer.Identity)
		if !identityOK || reviewer.Role == "" || reviewer.Decision != "ACCEPT" || reviewer.RunID == "" ||
			!validHTTPSURI(reviewer.RunURL) || !validHTTPSURI(reviewer.EvidenceRef) ||
			!digestPattern.MatchString(reviewer.EvidenceDigest) {
			return errors.New("technical reviewer disposition is incomplete")
		}
		expectedGateName, knownRole := reviewerGateByRole[reviewer.Role]
		if !knownRole || reviewer.GateName != expectedGateName {
			return errors.New("technical reviewer role must map to its fixed review gate")
		}
		gate, exists := gates[expectedGateName]
		if !exists || gate.RunURL != reviewer.RunURL || gate.RunID != reviewer.RunID ||
			gate.EvidenceRef != reviewer.EvidenceRef || gate.EvidenceDigest != reviewer.EvidenceDigest ||
			gate.Timestamp != reviewer.Timestamp {
			return errors.New("technical reviewer run, evidence, and timestamp must exactly match its review gate")
		}
		reviewerTime, err := parseTimestamp(reviewer.Timestamp, "reviewer timestamp")
		if err != nil {
			return err
		}
		if reviewerTime.After(createdAt) {
			return errors.New("reviewer timestamp must not be after manifest created_at")
		}
		if _, duplicate := identities[canonicalIdentity]; duplicate {
			return errors.New("reviewers contains a duplicate identity")
		}
		if _, duplicate := roles[reviewer.Role]; duplicate {
			return errors.New("reviewers contains a duplicate role")
		}
		identities[canonicalIdentity] = struct{}{}
		roles[reviewer.Role] = struct{}{}
	}
	for _, required := range requiredReviewerRoles {
		if _, exists := roles[required]; !exists {
			return fmt.Errorf("required technical reviewer role %q is missing", required)
		}
	}
	return nil
}

func validateRollback(rollback RollbackEvidence, candidateSHA string, worktreeClean bool, evidenceMode string, createdAt time.Time) error {
	if rollback.Status != "PASS" || !canonicalRunID.MatchString(rollback.RunID) ||
		!rawSHA256Pattern.MatchString(rollback.ContainmentNonce) ||
		rollback.ContainmentNonce == strings.Repeat("0", sha256.Size*2) ||
		!rawSHA256Pattern.MatchString(rollback.RunnerBinarySHA256) || !validHTTPSURI(rollback.EvidenceRef) ||
		!digestPattern.MatchString(rollback.EvidenceDigest) || !validHTTPSURI(rollback.InputLockRef) ||
		!digestPattern.MatchString(rollback.InputLockDigest) || strings.TrimSpace(rollback.ContainmentProfile) == "" ||
		!validHTTPSURI(rollback.ContainmentEvidenceRef) || !digestPattern.MatchString(rollback.ContainmentEvidenceDigest) ||
		rollback.CandidateSHA != candidateSHA ||
		!digestPattern.MatchString(rollback.CandidateBinaryDigest) || rollback.OldTag != "v0.2.0" ||
		rollback.OldTagSHA != rollbackV020SHA || !digestPattern.MatchString(rollback.OldBinaryDigest) {
		return errors.New("rollback evidence is incomplete or unbound")
	}
	rollbackTime, err := parseTimestamp(rollback.Timestamp, "rollback timestamp")
	if err != nil {
		return err
	}
	if rollbackTime.After(createdAt) {
		return errors.New("rollback timestamp must not be after manifest created_at")
	}
	startedAt, err := parseCanonicalUTCTimestamp(rollback.StartedAt, "rollback started_at")
	if err != nil {
		return err
	}
	endedAt, err := parseCanonicalUTCTimestamp(rollback.EndedAt, "rollback ended_at")
	if err != nil || endedAt.Before(startedAt) {
		return errors.New("rollback time range must be canonical UTC and ordered")
	}
	if rollback.Timestamp != rollback.EndedAt {
		return errors.New("rollback timestamp must equal rollback ended_at")
	}
	expectedEvidenceDigest, err := rollbackReportEvidenceDigest(rollback, worktreeClean, evidenceMode)
	if err != nil || rollback.EvidenceDigest != expectedEvidenceDigest {
		return errors.New("rollback evidence_digest must bind the exact local rollback report bytes")
	}
	return nil
}

func validateFindings(findings []Finding, acceptedList bool, createdAt time.Time) error {
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		if finding.ID == "" || strings.TrimSpace(finding.Description) == "" || strings.TrimSpace(finding.Mitigation) == "" ||
			!validHTTPSURI(finding.EvidenceRef) || !digestPattern.MatchString(finding.EvidenceDigest) ||
			(finding.Severity != "P2" && finding.Severity != "P3") {
			return errors.New("only identified P2/P3 findings may remain")
		}
		if _, duplicate := seen[finding.ID]; duplicate {
			return errors.New("duplicate finding ID")
		}
		seen[finding.ID] = struct{}{}
		if !finding.Accepted || finding.AcceptedBy == "" || finding.AcceptedAt == "" || finding.Owner == "" || finding.Deadline == "" {
			return errors.New("remaining finding requires explicit authority acceptance, owner, and deadline")
		}
		if acceptedList && !finding.Accepted {
			return errors.New("accepted risk is not accepted")
		}
		deadline, err := parseTimestamp(finding.Deadline, "finding deadline")
		if err != nil {
			return err
		}
		if !deadline.After(createdAt) {
			return errors.New("finding deadline must be after manifest created_at")
		}
		acceptedAt, err := parseTimestamp(finding.AcceptedAt, "finding accepted_at")
		if err != nil {
			return err
		}
		if acceptedAt.After(createdAt) {
			return errors.New("finding accepted_at must not be after manifest created_at")
		}
	}
	return nil
}

func validateClosure(rawManifest []byte, manifest *Manifest, closure *ReleaseClosure) error {
	if closure.SchemaVersion != "aegis.release-closure/v1" {
		return errors.New("unsupported closure schema_version")
	}
	createdAt, err := parseTimestamp(closure.CreatedAt, "closure created_at")
	if err != nil {
		return err
	}
	manifestTime, err := parseTimestamp(manifest.CreatedAt, "manifest created_at")
	if err != nil {
		return err
	}
	if createdAt.Before(manifestTime) {
		return errors.New("closure created_at must not be before manifest created_at")
	}
	manifestDigest := sha256.Sum256(rawManifest)
	if closure.ManifestDigest != "sha256:"+hex.EncodeToString(manifestDigest[:]) || !validHTTPSURI(closure.ManifestURI) {
		return errors.New("closure manifest identity is incomplete or unbound")
	}
	policy := manifest.ReleaseApprovalPolicy
	if !validHTTPSURI(closure.ApprovalRef) || !digestPattern.MatchString(closure.ApprovalDigest) ||
		closure.TrustPolicyURI != policy.TrustPolicyURI || closure.TrustPolicyDigest != policy.TrustPolicyDigest ||
		closure.VerifierURI != policy.VerifierURI || closure.VerifierDigest != policy.VerifierDigest {
		return errors.New("closure approval or trust-policy identity is incomplete or unbound")
	}
	if closure.ReleaseVersion != manifest.ReleaseVersion || closure.CandidateSHA != manifest.CandidateSHA ||
		closure.TagName != manifest.TagName || closure.TagObjectSHA != manifest.TagObjectSHA ||
		closure.TagTargetSHA != manifest.TagTargetSHA || closure.ArtifactScope != manifest.ArtifactScope.Decision ||
		!equalStrings(closure.ArtifactDigests, artifactDigestOrder(manifest.Artifacts)) {
		return errors.New("closure release, tag, candidate, or artifact identity does not match manifest")
	}
	if err := validateRecordedClosureCheck(closure.RemoteVerification, false); err != nil {
		return fmt.Errorf("remote_verification: %w", err)
	}
	if manifest.ArtifactScope.Decision == "source_tag_only" {
		if err := validateNotApplicableClosureCheck(closure.PublishedSmoke); err != nil {
			return fmt.Errorf("published_smoke: %w", err)
		}
	} else if err := validateRecordedClosureCheck(closure.PublishedSmoke, false); err != nil {
		return fmt.Errorf("published_smoke: %w", err)
	}
	monitorStart, err := parseTimestamp(closure.Monitoring.StartedAt, "monitoring started_at")
	if err != nil {
		return err
	}
	monitorEnd, err := parseTimestamp(closure.Monitoring.EndedAt, "monitoring ended_at")
	if err != nil {
		return err
	}
	if monitorStart.Before(manifestTime) || !monitorEnd.After(monitorStart) || createdAt.Before(monitorEnd) ||
		(closure.Monitoring.Status != "PASS" && closure.Monitoring.Status != "FAIL") ||
		!validHTTPSURI(closure.Monitoring.EvidenceRef) || !digestPattern.MatchString(closure.Monitoring.EvidenceDigest) {
		return errors.New("monitoring window or evidence is invalid")
	}
	if strings.TrimSpace(closure.OutcomeReason) == "" {
		return errors.New("closure outcome_reason is required")
	}
	switch closure.Outcome {
	case "RELEASED":
		if closure.Rollback != nil || closure.RemoteVerification.Status != "PASS" || closure.Monitoring.Status != "PASS" ||
			(manifest.ArtifactScope.Decision != "source_tag_only" && closure.PublishedSmoke.Status != "PASS") {
			return errors.New("RELEASED closure requires successful verification, smoke, and monitoring without rollback")
		}
	case "ROLLED_BACK":
		if closure.Rollback == nil || validateRecordedClosureCheck(*closure.Rollback, true) != nil {
			return errors.New("ROLLED_BACK closure requires PASS rollback evidence")
		}
	default:
		return errors.New("closure outcome must be RELEASED or ROLLED_BACK")
	}
	return nil
}

func validateRecordedClosureCheck(check ClosureCheck, passOnly bool) error {
	validStatus := check.Status == "PASS" || (!passOnly && check.Status == "FAIL")
	if !validStatus ||
		!validHTTPSURI(check.EvidenceRef) || !digestPattern.MatchString(check.EvidenceDigest) ||
		check.Justification != "" {
		return errors.New("recorded check requires status and content-addressed evidence")
	}
	return nil
}

func validateNotApplicableClosureCheck(check ClosureCheck) error {
	if check.Status != "NOT_APPLICABLE" || strings.TrimSpace(check.Justification) == "" ||
		check.EvidenceRef != "" || check.EvidenceDigest != "" {
		return errors.New("source_tag_only smoke requires only a NOT_APPLICABLE justification")
	}
	return nil
}

func validateApproval(rawManifest []byte, manifest *Manifest, approval *Approval) error {
	canonicalApprover, approverIdentityOK := canonicalASCIIIdentity(approval.ApproverIdentity)
	if approval.SchemaVersion != "aegis.release-approval/v1" || !approverIdentityOK ||
		approval.ApproverRole != manifest.ReleaseApprovalPolicy.RequiredRole ||
		approval.ApproverKeyID != manifest.ReleaseApprovalPolicy.RequiredKeyID || approval.Decision != "APPROVE" {
		return errors.New("approval identity, role, decision, or schema is invalid")
	}
	if err := requireTimestamp(approval.Timestamp, "approval timestamp"); err != nil {
		return err
	}
	approvalTime, _ := time.Parse(time.RFC3339, approval.Timestamp)
	manifestTime, err := parseTimestamp(manifest.CreatedAt, "manifest created_at")
	if err != nil {
		return err
	}
	if approvalTime.Before(manifestTime) {
		return errors.New("approval timestamp must not be before manifest created_at")
	}
	for _, reviewer := range manifest.Reviewers {
		canonicalReviewer, reviewerIdentityOK := canonicalASCIIIdentity(reviewer.Identity)
		if !reviewerIdentityOK || canonicalApprover == canonicalReviewer {
			return errors.New("independent approver must not be a technical reviewer")
		}
	}
	if approval.CandidateSHA != manifest.CandidateSHA {
		return errors.New("approval candidate_sha does not match manifest")
	}
	digest := sha256.Sum256(rawManifest)
	if approval.ManifestDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		return errors.New("approval manifest_digest does not match exact manifest bytes")
	}
	if len(approval.ArtifactDigests) != len(manifest.Artifacts) {
		return errors.New("approval artifact_digests length does not match manifest")
	}
	for index, artifact := range manifest.Artifacts {
		if approval.ArtifactDigests[index] != artifact.Digest {
			return errors.New("approval artifact_digests order does not match manifest")
		}
	}
	return nil
}

func validateApprovalSignature(rawApproval []byte, publicKeyHex, signatureHex, expectedKeyID string) error {
	publicKey, err := hex.DecodeString(strings.TrimSpace(publicKeyHex))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("trusted approver public key must be a hex Ed25519 key")
	}
	publicKeyDigest := sha256.Sum256(publicKey)
	if expectedKeyID != "sha256:"+hex.EncodeToString(publicKeyDigest[:]) {
		return errors.New("trusted approver key ID does not match the Ed25519 public key")
	}
	signature, err := hex.DecodeString(strings.TrimSpace(signatureHex))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("approval signature must be a hex Ed25519 signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), rawApproval, signature) {
		return errors.New("approval signature verification failed")
	}
	return nil
}

func foldEvidenceMemberName(value string) (string, bool) {
	folded := make([]byte, len(value))
	for index := range value {
		char := value[index]
		if char >= 0x80 {
			return "", false
		}
		if char >= 'A' && char <= 'Z' {
			char += 'a' - 'A'
		}
		folded[index] = char
	}
	return string(folded), true
}

func canonicalASCIIIdentity(value string) (string, bool) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", false
	}
	folded := make([]byte, len(value))
	for index := range value {
		char := value[index]
		if char < 0x20 || char > 0x7e {
			return "", false
		}
		if char >= 'A' && char <= 'Z' {
			char += 'a' - 'A'
		}
		folded[index] = char
	}
	return string(folded), true
}

func rollbackReportEvidenceDigest(rollback RollbackEvidence, worktreeClean bool, evidenceMode string) (string, error) {
	if evidenceMode != "FINAL" {
		return "", errors.New("unsupported rollback report evidence class")
	}
	report := rollbackReportBinding{
		SchemaVersion:         3,
		Result:                rollback.Status,
		EvidenceClass:         rollbackFinalEvidenceClass,
		WorktreeClean:         worktreeClean,
		RunID:                 rollback.RunID,
		ContainmentNonce:      rollback.ContainmentNonce,
		StartedAt:             rollback.StartedAt,
		EndedAt:               rollback.EndedAt,
		RunnerBinarySHA256:    rollback.RunnerBinarySHA256,
		CandidateSHA:          rollback.CandidateSHA,
		RollbackSourceSHA:     rollback.OldTagSHA,
		CandidateBinarySHA256: strings.TrimPrefix(rollback.CandidateBinaryDigest, "sha256:"),
		RollbackBinarySHA256:  strings.TrimPrefix(rollback.OldBinaryDigest, "sha256:"),
		InputLockDigest:       strings.TrimPrefix(rollback.InputLockDigest, "sha256:"),
		Migration:             rollbackMigrationResult,
		CurrentSmoke:          rollbackCurrentSmokeResult,
		Rollback:              rollbackRestoreResult,
	}
	var raw bytes.Buffer
	encoder := json.NewEncoder(&raw)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		return "", errors.New("encoding expected rollback report")
	}
	digest := sha256.Sum256(raw.Bytes())
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func artifactDigestOrder(artifacts []Artifact) []string {
	digests := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		digests = append(digests, artifact.Digest)
	}
	return digests
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func parseSafeAbsoluteURI(value string) (*url.URL, bool) {
	if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\t") {
		return nil, false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return nil, false
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.User != nil || parsed.Fragment != "" {
		return nil, false
	}
	return parsed, true
}

func validHTTPSURI(value string) bool {
	parsed, ok := parseSafeAbsoluteURI(value)
	return ok && parsed.Scheme == "https" && parsed.Hostname() != ""
}

func validImmutableArtifactURI(value string) bool {
	parsed, ok := parseSafeAbsoluteURI(value)
	if !ok {
		return false
	}
	switch parsed.Scheme {
	case "https", "oci", "release":
		return parsed.Hostname() != ""
	case "urn":
		return parsed.Opaque != ""
	default:
		return false
	}
}

func requireTimestamp(value, field string) error {
	_, err := parseTimestamp(value, field)
	return err
}

func parseTimestamp(value, field string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("%s is required", field)
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be RFC3339", field)
	}
	return parsed, nil
}

func parseCanonicalUTCTimestamp(value, field string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || !strings.HasSuffix(value, "Z") || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, fmt.Errorf("%s must be canonical UTC RFC3339", field)
	}
	return parsed, nil
}
