package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testCandidateSHA  = "1111111111111111111111111111111111111111"
	testTreeSHA       = "2222222222222222222222222222222222222222"
	testTagObjectSHA  = "3333333333333333333333333333333333333333"
	testOldTagSHA     = rollbackV020SHA
	testDigest        = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testOldDigest     = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testApproverKeyID = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	testRollbackRunID = "019ff59d-b35c-79c1-992c-2b51460e6255"
	testRollbackNonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testRunnerSHA256  = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	testRollbackStart = "2026-08-20T12:25:00Z"
	testRollbackEnd   = "2026-08-20T12:30:00Z"
)

func TestValidateManifestAcceptsBoundFinalSourceTagEvidence(t *testing.T) {
	manifest := validManifest()
	if err := validateManifest(&manifest); err != nil {
		t.Fatalf("validateManifest returned error: %v", err)
	}
}

func TestValidateManifestRejectsIdentityAndEvidenceDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "short candidate", mutate: func(m *Manifest) { m.CandidateSHA = "1111111" }},
		{name: "wrong release schema version", mutate: func(m *Manifest) {
			m.ReleaseVersion = "v0.2.2"
			m.TagName = "v0.2.2"
		}},
		{name: "lightweight tag identity", mutate: func(m *Manifest) { m.TagObjectSHA = m.TagTargetSHA }},
		{name: "dirty", mutate: func(m *Manifest) { m.WorktreeClean = false }},
		{name: "iteration evidence", mutate: func(m *Manifest) { m.EvidenceMode = "ITERATION_ONLY" }},
		{name: "tag target", mutate: func(m *Manifest) { m.TagTargetSHA = testOldTagSHA }},
		{name: "gate candidate", mutate: func(m *Manifest) { m.Gates[0].CandidateSHA = testOldTagSHA }},
		{name: "gate run URL", mutate: func(m *Manifest) { m.Gates[0].RunURL = "" }},
		{name: "gate evidence reference", mutate: func(m *Manifest) { m.Gates[0].EvidenceRef = "" }},
		{name: "relative gate evidence reference", mutate: func(m *Manifest) { m.Gates[0].EvidenceRef = "evidence.json" }},
		{name: "gate evidence digest", mutate: func(m *Manifest) { m.Gates[0].EvidenceDigest = "sha256:short" }},
		{name: "qa candidate", mutate: func(m *Manifest) { m.QA.SUTSHA = testOldTagSHA }},
		{name: "qa SUT binary digest", mutate: func(m *Manifest) { m.QA.SUTBinaryDigest = "sha256:short" }},
		{name: "container smoke image ID", mutate: func(m *Manifest) { m.ContainerSmoke.ImageID = "mutable-image-id" }},
		{name: "rollback candidate", mutate: func(m *Manifest) { m.Rollback.CandidateSHA = testOldTagSHA }},
		{name: "rollback old tag", mutate: func(m *Manifest) { m.Rollback.OldTagSHA = strings.Repeat("f", 40) }},
		{name: "rollback evidence", mutate: func(m *Manifest) { m.Rollback.EvidenceRef = "" }},
		{name: "rollback input lock", mutate: func(m *Manifest) { m.Rollback.InputLockDigest = "sha256:short" }},
		{name: "rollback containment", mutate: func(m *Manifest) { m.Rollback.ContainmentEvidenceRef = "" }},
		{name: "open p1", mutate: func(m *Manifest) {
			m.OpenFindings = []Finding{{ID: "SEC-1", Severity: "P1", Accepted: true, Owner: "release-owner", Deadline: "2026-09-01T00:00:00Z"}}
		}},
		{name: "open accepted p2", mutate: func(m *Manifest) {
			m.OpenFindings = []Finding{{ID: "SEC-2", Severity: "P2", Accepted: true, Owner: "release-owner", Deadline: "2026-09-01T00:00:00Z"}}
		}},
		{name: "unverified surface", mutate: func(m *Manifest) { m.UnverifiedSurfaces = []string{"real provider"} }},
		{name: "gate after manifest creation", mutate: func(m *Manifest) { m.Gates[0].Timestamp = "2026-08-20T12:41:00Z" }},
		{name: "duplicate reviewer identity", mutate: func(m *Manifest) { m.Reviewers[1].Identity = m.Reviewers[0].Identity }},
		{name: "missing trust policy URI", mutate: func(m *Manifest) { m.ReleaseApprovalPolicy.TrustPolicyURI = "" }},
		{name: "relative trust policy URI", mutate: func(m *Manifest) { m.ReleaseApprovalPolicy.TrustPolicyURI = "trust-policy.json" }},
		{name: "userinfo trust policy URI", mutate: func(m *Manifest) { m.ReleaseApprovalPolicy.TrustPolicyURI = "https://user@example.com/policy" }},
		{name: "invalid trust policy digest", mutate: func(m *Manifest) { m.ReleaseApprovalPolicy.TrustPolicyDigest = "sha256:short" }},
		{name: "missing verifier URI", mutate: func(m *Manifest) { m.ReleaseApprovalPolicy.VerifierURI = "" }},
		{name: "invalid verifier digest", mutate: func(m *Manifest) { m.ReleaseApprovalPolicy.VerifierDigest = "sha256:short" }},
		{name: "invalid accepted-risk deadline", mutate: func(m *Manifest) {
			m.AcceptedRisks = []Finding{{ID: "RISK-1", Severity: "P2", Accepted: true, Owner: "release-owner", Deadline: "never"}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := validManifest()
			tt.mutate(&manifest)
			if err := validateManifest(&manifest); err == nil {
				t.Fatal("validateManifest accepted drifted final evidence")
			}
		})
	}
}

func TestValidateManifestAcceptsAuthorityBoundResidualRisk(t *testing.T) {
	manifest := validManifest()
	manifest.AcceptedRisks = []Finding{{
		ID:             "RISK-INGRESS-1",
		Severity:       "P2",
		Description:    "standalone limiter is per virtual key",
		Mitigation:     "deploy behind the approved trusted ingress limits",
		EvidenceRef:    "https://evidence.example/aegis/risks/ingress.json",
		EvidenceDigest: testDigest,
		Accepted:       true,
		AcceptedBy:     "release-authority@example.com",
		AcceptedAt:     "2026-08-20T12:35:00Z",
		Owner:          "runtime-owner@example.com",
		Deadline:       "2026-09-20T12:40:00Z",
	}}
	if err := validateManifest(&manifest); err != nil {
		t.Fatalf("validateManifest rejected authority-bound residual risk: %v", err)
	}

	manifest.AcceptedRisks[0].EvidenceDigest = "sha256:short"
	if err := validateManifest(&manifest); err == nil {
		t.Fatal("validateManifest accepted residual risk without immutable evidence")
	}
}

func TestValidateManifestRejectsGateEvidenceBindingMismatches(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "independent qa run id", mutate: func(m *Manifest) { m.QA.RunID = "different-run" }},
		{name: "independent qa run URL", mutate: func(m *Manifest) {
			m.QA.RunURL = "https://evidence.example/aegis/runs/different-independent-qa"
		}},
		{name: "independent qa evidence reference", mutate: func(m *Manifest) {
			m.QA.EvidenceRef = "https://evidence.example/aegis/gates/different-independent-qa"
		}},
		{name: "independent qa evidence digest", mutate: func(m *Manifest) { m.QA.EvidenceBundleDigest = testOldDigest }},
		{name: "container smoke run id", mutate: func(m *Manifest) { m.ContainerSmoke.RunID = "different-container-run" }},
		{name: "container smoke run URL", mutate: func(m *Manifest) {
			m.ContainerSmoke.RunURL = "https://evidence.example/aegis/runs/different-container-smoke"
		}},
		{name: "container smoke evidence reference", mutate: func(m *Manifest) {
			m.ContainerSmoke.EvidenceRef = "https://evidence.example/aegis/gates/different-container-smoke"
		}},
		{name: "container smoke evidence digest", mutate: func(m *Manifest) { m.ContainerSmoke.EvidenceDigest = testOldDigest }},
		{name: "container smoke timestamp", mutate: func(m *Manifest) { m.ContainerSmoke.Timestamp = "2026-08-20T12:11:00Z" }},
		{name: "source-only smoke claims published artifact", mutate: func(m *Manifest) {
			m.ContainerSmoke.ArtifactBinding = "PUBLISHED_ARTIFACT"
		}},
		{name: "rollback run id", mutate: func(m *Manifest) { m.Rollback.RunID = "different-rollback-run" }},
		{name: "rollback evidence reference", mutate: func(m *Manifest) {
			m.Rollback.EvidenceRef = "https://evidence.example/aegis/rollback/different-report.json"
		}},
		{name: "rollback evidence digest", mutate: func(m *Manifest) { m.Rollback.EvidenceDigest = testOldDigest }},
		{name: "rollback timestamp", mutate: func(m *Manifest) { m.Rollback.Timestamp = "2026-08-20T12:31:00Z" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := validManifest()
			tt.mutate(&manifest)
			if err := validateManifest(&manifest); err == nil {
				t.Fatal("validateManifest accepted mismatched gate evidence identity")
			}
		})
	}
}

func TestValidateManifestRejectsRollbackReportSplice(t *testing.T) {
	reportManifest := validManifest()
	if err := validateManifest(&reportManifest); err != nil {
		t.Fatalf("validateManifest rejected the manifest bound to rollback report X: %v", err)
	}

	splicedManifest := reportManifest
	splicedManifest.Rollback.InputLockDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if err := validateManifest(&splicedManifest); err == nil {
		t.Fatal("validateManifest accepted rollback report X with manifest Y input-lock identity")
	}
}

func TestDecodeAndValidateManifestAcceptsCanonicalRollbackReportV3Binding(t *testing.T) {
	raw := validManifestWithRollbackReportV3(t)
	manifest, err := decodeManifest(raw)
	if err != nil {
		t.Fatalf("decodeManifest rejected canonical rollback report v3 fields: %v", err)
	}
	if err := validateManifest(&manifest); err != nil {
		t.Fatalf("validateManifest rejected canonical rollback report v3 binding: %v", err)
	}
}

func TestValidateManifestRejectsRollbackReportV3FormatAndBindingMismatches(t *testing.T) {
	tests := []struct {
		name                string
		rebindInvalidReport bool
		mutate              func(*testing.T, []byte) []byte
	}{
		{name: "missing containment nonce", rebindInvalidReport: true, mutate: func(t *testing.T, raw []byte) []byte {
			return replaceManifestBytes(t, raw, `,"containment_nonce":"`+testRollbackNonce+`"`, "", 1)
		}},
		{name: "missing started at", rebindInvalidReport: true, mutate: func(t *testing.T, raw []byte) []byte {
			return replaceManifestBytes(t, raw, `,"started_at":"`+testRollbackStart+`"`, "", 1)
		}},
		{name: "missing ended at", rebindInvalidReport: true, mutate: func(t *testing.T, raw []byte) []byte {
			return replaceManifestBytes(t, raw, `,"ended_at":"`+testRollbackEnd+`"`, "", 1)
		}},
		{name: "missing runner binary digest", rebindInvalidReport: true, mutate: func(t *testing.T, raw []byte) []byte {
			return replaceManifestBytes(t, raw,
				`,"runner_binary_sha256":"`+testRunnerSHA256+`"`, "", 1)
		}},
		{name: "zero containment nonce", rebindInvalidReport: true, mutate: func(t *testing.T, raw []byte) []byte {
			return replaceManifestBytes(t, raw, testRollbackNonce, strings.Repeat("0", 64), 1)
		}},
		{name: "invalid runner binary digest", rebindInvalidReport: true, mutate: func(t *testing.T, raw []byte) []byte {
			return replaceManifestBytes(t, raw,
				`"runner_binary_sha256":"`+testRunnerSHA256+`"`,
				`"runner_binary_sha256":"short"`, 1)
		}},
		{name: "noncanonical started at", rebindInvalidReport: true, mutate: func(t *testing.T, raw []byte) []byte {
			return replaceManifestBytes(t, raw, testRollbackStart, "2026-08-20T12:25:00+00:00", 1)
		}},
		{name: "ended before started", rebindInvalidReport: true, mutate: func(t *testing.T, raw []byte) []byte {
			return replaceManifestBytes(t, raw, `"ended_at":"`+testRollbackEnd+`"`, `"ended_at":"2026-08-20T12:24:59Z"`, 1)
		}},
		{name: "noncanonical run id in gate and rollback", rebindInvalidReport: true, mutate: func(t *testing.T, raw []byte) []byte {
			return replaceManifestBytes(t, raw, testRollbackRunID, "rollback-run-1", 2)
		}},
		{name: "canonical containment nonce splice", mutate: func(t *testing.T, raw []byte) []byte {
			return replaceManifestBytes(t, raw, testRollbackNonce, strings.Repeat("d", 64), 1)
		}},
		{name: "canonical runner digest splice", mutate: func(t *testing.T, raw []byte) []byte {
			return replaceManifestBytes(t, raw,
				`"runner_binary_sha256":"`+testRunnerSHA256+`"`,
				`"runner_binary_sha256":"`+strings.Repeat("f", 64)+`"`, 1)
		}},
		{name: "canonical time-window splice", mutate: func(t *testing.T, raw []byte) []byte {
			return replaceManifestBytes(t, raw, testRollbackStart, "2026-08-20T12:26:00Z", 1)
		}},
		{name: "canonical run id splice in gate and rollback", mutate: func(t *testing.T, raw []byte) []byte {
			return replaceManifestBytes(t, raw, testRollbackRunID, "019ff59d-b35c-79c1-992c-2b51460e6256", 2)
		}},
		{name: "gate and rollback timestamp drift from report end", rebindInvalidReport: true, mutate: func(t *testing.T, raw []byte) []byte {
			return replaceManifestBytes(t, raw, `"timestamp":"`+testRollbackEnd+`"`, `"timestamp":"2026-08-20T12:31:00Z"`, 2)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := tt.mutate(t, validManifestWithRollbackReportV3(t))
			manifest, err := decodeManifest(raw)
			if err != nil {
				t.Errorf("decodeManifest rejected the v3-shaped negative fixture before semantic validation: %v", err)
				return
			}
			if tt.rebindInvalidReport {
				bindRollbackReportFixture(&manifest)
			}
			if err := validateManifest(&manifest); err == nil {
				t.Fatal("validateManifest accepted invalid or spliced rollback report v3 identity")
			}
		})
	}
}

func TestValidateManifestRejectsUnsafeEvidenceURISchemes(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "file trust policy", mutate: func(m *Manifest) { m.ReleaseApprovalPolicy.TrustPolicyURI = "file:///etc/passwd" }},
		{name: "data verifier", mutate: func(m *Manifest) { m.ReleaseApprovalPolicy.VerifierURI = "data:text/plain,verifier" }},
		{name: "javascript gate evidence", mutate: func(m *Manifest) {
			m.Gates[0].EvidenceRef = "javascript:alert(1)"
		}},
		{name: "file qa evidence", mutate: func(m *Manifest) { m.QA.EvidenceRef = "file:///tmp/qa.json" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := validManifest()
			tt.mutate(&manifest)
			if err := validateManifest(&manifest); err == nil {
				t.Fatal("validateManifest accepted an unsafe evidence URI scheme")
			}
		})
	}
}

func TestHTTPSURIValidatorRejectsAuthorityWithoutHostname(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "empty hostname with port", value: "https://:443/evidence"},
		{name: "userinfo", value: "https://user@example.com/evidence"},
		{name: "fragment", value: "https://example.com/evidence#section"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if validHTTPSURI(tt.value) {
				t.Fatalf("validHTTPSURI accepted unsafe authority: %q", tt.value)
			}
		})
	}
}

func TestImmutableArtifactURIValidatorRejectsAuthorityWithoutHostname(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "https empty hostname with port", value: "https://:443/artifact"},
		{name: "oci empty hostname with port", value: "oci://:443/artifact"},
		{name: "release empty hostname with port", value: "release://:443/artifact"},
		{name: "userinfo", value: "oci://user@registry.example/artifact"},
		{name: "fragment", value: "release://registry.example/artifact#section"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if validImmutableArtifactURI(tt.value) {
				t.Fatalf("validImmutableArtifactURI accepted unsafe authority: %q", tt.value)
			}
		})
	}
}

func TestValidateManifestRejectsReviewerGateBindingMismatches(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "run URL", mutate: func(m *Manifest) {
			m.Reviewers[0].RunURL = "https://evidence.example/aegis/runs/different-security-review"
		}},
		{name: "run id", mutate: func(m *Manifest) { m.Reviewers[0].RunID = "different-security-review" }},
		{name: "evidence reference", mutate: func(m *Manifest) {
			m.Reviewers[0].EvidenceRef = "https://evidence.example/aegis/gates/different-security-review"
		}},
		{name: "evidence digest", mutate: func(m *Manifest) { m.Reviewers[0].EvidenceDigest = testOldDigest }},
		{name: "timestamp", mutate: func(m *Manifest) { m.Reviewers[0].Timestamp = "2026-08-20T12:19:00Z" }},
		{name: "role gate swap", mutate: func(m *Manifest) {
			m.Reviewers[0].GateName, m.Reviewers[1].GateName = m.Reviewers[1].GateName, m.Reviewers[0].GateName
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := validManifest()
			tt.mutate(&manifest)
			if err := validateManifest(&manifest); err == nil {
				t.Fatal("validateManifest accepted a reviewer spliced from a different review gate")
			}
		})
	}
}

func TestValidateManifestRejectsNonCanonicalReviewerIdentities(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "leading whitespace", mutate: func(m *Manifest) { m.Reviewers[0].Identity = " security-review" }},
		{name: "trailing whitespace", mutate: func(m *Manifest) { m.Reviewers[0].Identity = "security-review " }},
		{name: "ASCII case-folded duplicate", mutate: func(m *Manifest) {
			m.Reviewers[1].Identity = strings.ToUpper(m.Reviewers[0].Identity)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := validManifest()
			tt.mutate(&manifest)
			if err := validateManifest(&manifest); err == nil {
				t.Fatal("validateManifest accepted a non-canonical reviewer identity")
			}
		})
	}
}

func TestValidateManifestEnforcesArtifactScopeAndDigestBindings(t *testing.T) {
	artifact := Artifact{
		Type:        "binary",
		Platform:    "linux/amd64",
		Reference:   "release://v0.2.1/aegis-linux-amd64",
		Digest:      testDigest,
		SourceSHA:   testCandidateSHA,
		EmbeddedSHA: testCandidateSHA,
		Toolchain:   "go1.26.6",
		SBOM:        Attestation{Status: "present", Reference: "release://sbom", Digest: testOldDigest},
		Signature:   Attestation{Status: "present", Reference: "release://signature", Digest: testOldDigest},
		Provenance:  Attestation{Status: "present", Reference: "release://provenance", Digest: testOldDigest},
	}

	manifest := validManifest()
	manifest.ArtifactScope.Decision = "binaries"
	manifest.Artifacts = []Artifact{artifact}
	bindBuiltArtifacts(&manifest)
	if err := validateManifest(&manifest); err != nil {
		t.Fatalf("validateManifest rejected bound binary evidence: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "source scope with artifact", mutate: func(m *Manifest) { m.ArtifactScope.Decision = "source_tag_only" }},
		{name: "artifact source", mutate: func(m *Manifest) { m.Artifacts[0].SourceSHA = testOldTagSHA }},
		{name: "embedded source", mutate: func(m *Manifest) { m.Artifacts[0].EmbeddedSHA = testOldTagSHA }},
		{name: "unsafe artifact reference", mutate: func(m *Manifest) { m.Artifacts[0].Reference = "file:///tmp/aegis" }},
		{name: "gate artifact", mutate: func(m *Manifest) { m.Gates[0].ArtifactDigests = []string{testOldDigest} }},
		{name: "missing sbom", mutate: func(m *Manifest) { m.Artifacts[0].SBOM = Attestation{} }},
		{name: "sbom not applicable", mutate: func(m *Manifest) {
			m.Artifacts[0].SBOM = Attestation{Status: "not_applicable", Justification: "n/a"}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := manifest
			candidate.Artifacts = append([]Artifact(nil), manifest.Artifacts...)
			candidate.Gates = append([]Gate(nil), manifest.Gates...)
			tt.mutate(&candidate)
			if err := validateManifest(&candidate); err == nil {
				t.Fatal("validateManifest accepted unbound artifact evidence")
			}
		})
	}
}

func TestValidateManifestRequiresPublishedContainerDigestBinding(t *testing.T) {
	manifest := validManifest()
	manifest.ArtifactScope.Decision = "container_images"
	manifest.Artifacts = []Artifact{{
		Type:        "container",
		Platform:    "linux/arm64",
		Reference:   "oci://registry.example/aegis@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Digest:      testDigest,
		SourceSHA:   testCandidateSHA,
		EmbeddedSHA: testCandidateSHA,
		Toolchain:   "go1.26.6",
		SBOM:        Attestation{Status: "present", Reference: "release://sbom", Digest: testOldDigest},
		Signature:   Attestation{Status: "present", Reference: "release://signature", Digest: testOldDigest},
		Provenance:  Attestation{Status: "present", Reference: "release://provenance", Digest: testOldDigest},
	}}
	bindBuiltArtifacts(&manifest)
	manifest.ContainerSmoke.ArtifactBinding = "PUBLISHED_ARTIFACT"
	manifest.ContainerSmoke.ImageDigest = testDigest
	if err := validateManifest(&manifest); err != nil {
		t.Fatalf("validateManifest rejected a published container bound to smoke evidence: %v", err)
	}

	manifest.ContainerSmoke.ImageDigest = testOldDigest
	if err := validateManifest(&manifest); err == nil {
		t.Fatal("validateManifest accepted smoke evidence for an unpublished container digest")
	}
}

func TestValidateManifestRejectsMultipleContainersWithOneSmokeIdentity(t *testing.T) {
	manifest := validManifest()
	manifest.ArtifactScope.Decision = "container_images"
	manifest.Artifacts = []Artifact{
		testContainerArtifact(
			"linux/arm64",
			"oci://registry.example/aegis@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			testDigest,
			"arm64",
			testOldDigest,
		),
		testContainerArtifact(
			"linux/amd64",
			"oci://registry.example/aegis@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			"amd64",
			"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		),
	}
	bindBuiltArtifacts(&manifest)
	manifest.ContainerSmoke.ArtifactBinding = "PUBLISHED_ARTIFACT"
	manifest.ContainerSmoke.ImageDigest = testDigest

	if err := validateManifest(&manifest); err == nil {
		t.Fatal("validateManifest accepted container artifacts A+B with a single smoke identity for A")
	}
}

func TestValidateManifestRejectsQABinaryDigestOutsidePublishedBinaries(t *testing.T) {
	manifest := validManifest()
	manifest.ArtifactScope.Decision = "binaries"
	manifest.Artifacts = []Artifact{testBinaryArtifact(
		"linux/amd64",
		"release://v0.2.1/aegis-linux-amd64",
		testDigest,
		"amd64",
		testOldDigest,
	)}
	bindBuiltArtifacts(&manifest)
	manifest.QA.SUTBinaryDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	if err := validateManifest(&manifest); err == nil {
		t.Fatal("validateManifest accepted qa.sut_binary_digest B when the published binary digest is A")
	}
}

func TestValidateManifestRequiresCanonicalBuiltScopeAttestationSummary(t *testing.T) {
	build := func() Manifest {
		manifest := validManifest()
		manifest.ArtifactScope.Decision = "binaries"
		manifest.Artifacts = []Artifact{testBinaryArtifact(
			"linux/amd64",
			"release://v0.2.1/aegis-linux-amd64",
			testDigest,
			"amd64",
			testOldDigest,
		)}
		bindBuiltArtifacts(&manifest)
		return manifest
	}

	manifest := build()
	if err := validateManifest(&manifest); err != nil {
		t.Fatalf("validateManifest rejected canonical built-scope attestation summary: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "present second truth surface", mutate: func(m *Manifest) {
			m.ArtifactScope.SBOM = Attestation{Status: "present", Reference: "https://evidence.example/sbom.json", Digest: testOldDigest}
		}},
		{name: "unsafe second truth surface", mutate: func(m *Manifest) {
			m.ArtifactScope.Signature = Attestation{Status: "present", Reference: "file:///tmp/signature", Digest: testOldDigest}
		}},
		{name: "bad digest second truth surface", mutate: func(m *Manifest) {
			m.ArtifactScope.Provenance = Attestation{Status: "present", Reference: "https://evidence.example/provenance.json", Digest: "sha256:short"}
		}},
		{name: "arbitrary justification", mutate: func(m *Manifest) {
			m.ArtifactScope.SBOM.Justification = "recorded somewhere else"
		}},
		{name: "canonical status with reference", mutate: func(m *Manifest) {
			m.ArtifactScope.Signature.Reference = "https://evidence.example/unexpected-signature.json"
		}},
		{name: "canonical status with digest", mutate: func(m *Manifest) {
			m.ArtifactScope.Provenance.Digest = testOldDigest
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := build()
			tt.mutate(&candidate)
			if err := validateManifest(&candidate); err == nil {
				t.Fatal("validateManifest accepted a non-canonical built-scope attestation summary")
			}
		})
	}
}

func TestValidateManifestBindsOrderedPerArtifactAttestationEvidence(t *testing.T) {
	build := func() Manifest {
		manifest := validManifest()
		manifest.ArtifactScope.Decision = "binaries"
		manifest.Artifacts = []Artifact{
			testBinaryArtifact("linux/amd64", "release://v0.2.1/aegis-linux-amd64", testDigest, "amd64", testOldDigest),
			testBinaryArtifact(
				"linux/arm64",
				"release://v0.2.1/aegis-linux-arm64",
				"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				"arm64",
				"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			),
		}
		bindBuiltArtifacts(&manifest)
		return manifest
	}

	manifest := build()
	if err := validateManifest(&manifest); err != nil {
		t.Fatalf("validateManifest rejected ordered per-artifact attestation evidence: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "sbom reference order", mutate: func(m *Manifest) {
			gate := testGate(m, "sbom-verify")
			gate.AttestationReferences[0], gate.AttestationReferences[1] = gate.AttestationReferences[1], gate.AttestationReferences[0]
		}},
		{name: "signature digest mismatch", mutate: func(m *Manifest) {
			testGate(m, "artifact-signature-verify").AttestationDigests[0] = testDigest
		}},
		{name: "missing provenance reference", mutate: func(m *Manifest) {
			testGate(m, "provenance-verify").AttestationReferences = nil
		}},
		{name: "unrelated gate claims attestation", mutate: func(m *Manifest) {
			gate := testGate(m, "go-test")
			gate.AttestationReferences = []string{m.Artifacts[0].SBOM.Reference}
			gate.AttestationDigests = []string{m.Artifacts[0].SBOM.Digest}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := build()
			tt.mutate(&candidate)
			if err := validateManifest(&candidate); err == nil {
				t.Fatal("validateManifest accepted spliced per-artifact attestation evidence")
			}
		})
	}
}

func TestGateJSONOmitsEmptyAttestationBindings(t *testing.T) {
	raw, err := json.Marshal(validManifest().Gates[0])
	if err != nil {
		t.Fatalf("Marshal gate: %v", err)
	}
	if bytes.Contains(raw, []byte(`"attestation_references"`)) || bytes.Contains(raw, []byte(`"attestation_digests"`)) {
		t.Fatalf("empty attestation bindings were serialized: %s", raw)
	}
}

func TestValidateApprovalBindsFinalManifestDigestAndOrderedArtifacts(t *testing.T) {
	manifest := validManifest()
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	digest := sha256.Sum256(raw)
	approval := Approval{
		SchemaVersion:    "aegis.release-approval/v1",
		ApproverIdentity: "qa@example.com",
		ApproverRole:     "independent-release-approver",
		ApproverKeyID:    testApproverKeyID,
		Decision:         "APPROVE",
		Timestamp:        "2026-08-20T12:45:00Z",
		ManifestDigest:   "sha256:" + hex.EncodeToString(digest[:]),
		CandidateSHA:     testCandidateSHA,
		ArtifactDigests:  []string{},
	}
	if err := validateApproval(raw, &manifest, &approval); err != nil {
		t.Fatalf("validateApproval returned error: %v", err)
	}

	approval.CandidateSHA = testOldTagSHA
	if err := validateApproval(raw, &manifest, &approval); err == nil {
		t.Fatal("validateApproval accepted a mismatched candidate")
	}

	approval.CandidateSHA = testCandidateSHA
	approval.ApproverIdentity = manifest.Reviewers[0].Identity
	if err := validateApproval(raw, &manifest, &approval); err == nil {
		t.Fatal("validateApproval accepted a technical reviewer as the independent approver")
	}
}

func TestValidateApprovalRejectsNonCanonicalApproverIdentities(t *testing.T) {
	manifest := validManifest()
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	digest := sha256.Sum256(raw)
	newApproval := func(identity string) Approval {
		return Approval{
			SchemaVersion:    "aegis.release-approval/v1",
			ApproverIdentity: identity,
			ApproverRole:     "independent-release-approver",
			ApproverKeyID:    testApproverKeyID,
			Decision:         "APPROVE",
			Timestamp:        "2026-08-20T12:45:00Z",
			ManifestDigest:   "sha256:" + hex.EncodeToString(digest[:]),
			CandidateSHA:     testCandidateSHA,
			ArtifactDigests:  []string{},
		}
	}

	for _, identity := range []string{" qa@example.com", "qa@example.com "} {
		approval := newApproval(identity)
		if err := validateApproval(raw, &manifest, &approval); err == nil {
			t.Fatalf("validateApproval accepted approver identity with boundary whitespace: %q", identity)
		}
	}

	approval := newApproval(strings.ToUpper(manifest.Reviewers[0].Identity))
	if err := validateApproval(raw, &manifest, &approval); err == nil {
		t.Fatal("validateApproval accepted an ASCII case-folded technical reviewer identity as independent")
	}
}

func TestDecodeManifestRejectsUnknownDuplicateAndTrailingData(t *testing.T) {
	manifest := validManifest()
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}

	unknown := append([]byte(nil), raw[:len(raw)-1]...)
	unknown = append(unknown, []byte(`,"manifest_digest":"must-not-self-reference"}`)...)
	duplicate := []byte(strings.Replace(string(raw), `"candidate_sha":"`+testCandidateSHA+`"`, `"candidate_sha":"`+testCandidateSHA+`","candidate_sha":"`+testCandidateSHA+`"`, 1))
	caseCollision := []byte(strings.Replace(string(raw), `"candidate_sha":"`+testCandidateSHA+`"`, `"candidate_sha":"`+testCandidateSHA+`","Candidate_SHA":"`+testCandidateSHA+`"`, 1))
	caseMismatch := []byte(strings.Replace(string(raw), `"candidate_sha":"`+testCandidateSHA+`"`, `"Candidate_SHA":"`+testCandidateSHA+`"`, 1))
	trailing := append(append([]byte(nil), raw...), []byte(` {}`)...)
	invalidUTF8 := bytes.Replace(raw, []byte(`"release_version":"v0.2.1"`), []byte{'"', 'r', 'e', 'l', 'e', 'a', 's', 'e', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n', '"', ':', '"', 0xff, '"'}, 1)
	loneSurrogate := bytes.Replace(raw, []byte(`"release_version":"v0.2.1"`), []byte(`"release_version":"\ud800"`), 1)
	for name, input := range map[string][]byte{
		"unknown": unknown, "duplicate": duplicate, "case_collision": caseCollision, "case_mismatch": caseMismatch, "trailing": trailing,
		"invalid_utf8": invalidUTF8, "lone_surrogate": loneSurrogate,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeManifest(input); err == nil {
				t.Fatal("decodeManifest accepted ambiguous manifest JSON")
			}
		})
	}
}

func TestDecodeApprovalAndClosureRejectCaseMismatchedSchemaKeys(t *testing.T) {
	approvalRaw, err := json.Marshal(Approval{SchemaVersion: "aegis.release-approval/v1"})
	if err != nil {
		t.Fatalf("Marshal approval: %v", err)
	}
	approvalRaw = bytes.Replace(approvalRaw, []byte(`"schema_version"`), []byte(`"Schema_Version"`), 1)
	if _, err := decodeApproval(approvalRaw); err == nil {
		t.Fatal("decodeApproval accepted a case-mismatched schema key")
	}

	closureRaw, err := json.Marshal(ReleaseClosure{SchemaVersion: "aegis.release-closure/v1"})
	if err != nil {
		t.Fatalf("Marshal closure: %v", err)
	}
	closureRaw = bytes.Replace(closureRaw, []byte(`"schema_version"`), []byte(`"Schema_Version"`), 1)
	if _, err := decodeClosure(closureRaw); err == nil {
		t.Fatal("decodeClosure accepted a case-mismatched schema key")
	}
}

func TestRejectDuplicateMembersBoundsJSONComplexity(t *testing.T) {
	deep := append(bytes.Repeat([]byte("["), maxEvidenceJSONDepth+1), '0')
	deep = append(deep, bytes.Repeat([]byte("]"), maxEvidenceJSONDepth+1)...)
	if err := rejectDuplicateMembers(deep); err == nil {
		t.Fatal("rejectDuplicateMembers accepted excessive nesting")
	}

	var wide bytes.Buffer
	wide.WriteByte('{')
	for index := 0; index <= maxEvidenceJSONObjectMembers; index++ {
		if index > 0 {
			wide.WriteByte(',')
		}
		_, _ = fmt.Fprintf(&wide, "%q:0", fmt.Sprintf("field_%d", index))
	}
	wide.WriteByte('}')
	if err := rejectDuplicateMembers(wide.Bytes()); err == nil {
		t.Fatal("rejectDuplicateMembers accepted excessive object width")
	}
}

func TestRunNeverClaimsFinalValidWithoutCryptographicApproval(t *testing.T) {
	manifest := validManifest()
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile manifest: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-manifest", path}, &stdout, &stderr); code == 0 {
		t.Fatal("run accepted final validation without approval inputs")
	}
	if strings.Contains(stdout.String(), "VALID") {
		t.Fatalf("final-valid token emitted without approval: %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-manifest", path, "-schema-only"}, &stdout, &stderr); code != 0 {
		t.Fatalf("schema-only run exit = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "SCHEMA_VALID_NOT_RELEASE_APPROVED") {
		t.Fatalf("schema-only output = %q", stdout.String())
	}
}

func TestValidateApprovalSignatureRejectsForgery(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rawApproval := []byte(`{"decision":"APPROVE"}`)
	signature := ed25519.Sign(privateKey, rawApproval)
	keyDigest := sha256.Sum256(publicKey)
	keyID := "sha256:" + hex.EncodeToString(keyDigest[:])
	if err := validateApprovalSignature(rawApproval, hex.EncodeToString(publicKey), hex.EncodeToString(signature), keyID); err != nil {
		t.Fatalf("validateApprovalSignature rejected authentic signature: %v", err)
	}
	signature[0] ^= 0xff
	if err := validateApprovalSignature(rawApproval, hex.EncodeToString(publicKey), hex.EncodeToString(signature), keyID); err == nil {
		t.Fatal("validateApprovalSignature accepted forged signature")
	}
	if err := validateApprovalSignature(rawApproval, hex.EncodeToString(publicKey), hex.EncodeToString(ed25519.Sign(privateKey, rawApproval)), testApproverKeyID); err == nil {
		t.Fatal("validateApprovalSignature accepted a public key that did not match approver_key_id")
	}
}

func TestRunDoesNotTrustCallerSelectedApprovalKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyDigest := sha256.Sum256(publicKey)
	keyID := "sha256:" + hex.EncodeToString(keyDigest[:])
	manifest := validManifest()
	manifest.ReleaseApprovalPolicy.RequiredKeyID = keyID
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	manifestDigest := sha256.Sum256(rawManifest)
	approval := Approval{
		SchemaVersion: "aegis.release-approval/v1", ApproverIdentity: "self-selected@example.com",
		ApproverRole: "independent-release-approver", ApproverKeyID: keyID, Decision: "APPROVE",
		Timestamp: "2026-08-20T12:45:00Z", ManifestDigest: "sha256:" + hex.EncodeToString(manifestDigest[:]),
		CandidateSHA: testCandidateSHA, ArtifactDigests: []string{},
	}
	rawApproval, err := json.Marshal(approval)
	if err != nil {
		t.Fatalf("Marshal approval: %v", err)
	}
	signature := ed25519.Sign(privateKey, rawApproval)
	root := t.TempDir()
	write := func(name string, value []byte) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
		return path
	}
	manifestPath := write("manifest.json", rawManifest)
	approvalPath := write("approval.json", rawApproval)
	signaturePath := write("approval.sig", []byte(hex.EncodeToString(signature)))
	publicKeyPath := write("approver.pub", []byte(hex.EncodeToString(publicKey)))

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-manifest", manifestPath, "-approval", approvalPath, "-approval-signature", signaturePath,
		"-approver-public-key", publicKeyPath, "-expected-approver-identity", approval.ApproverIdentity,
		"-expected-approver-role", approval.ApproverRole, "-expected-approver-key-id", keyID,
	}, &stdout, &stderr)
	if code == 0 || strings.HasPrefix(stdout.String(), "VALID ") {
		t.Fatalf("caller-selected trust anchor produced final validity: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestValidateClosureBindsSourceOnlyReleaseOutcome(t *testing.T) {
	manifest := validManifest()
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	closure := validClosure(rawManifest, manifest)
	if err := validateClosure(rawManifest, &manifest, &closure); err != nil {
		t.Fatalf("validateClosure rejected bound closure: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ReleaseClosure)
	}{
		{name: "manifest digest", mutate: func(c *ReleaseClosure) { c.ManifestDigest = testOldDigest }},
		{name: "candidate", mutate: func(c *ReleaseClosure) { c.CandidateSHA = testOldTagSHA }},
		{name: "trust policy", mutate: func(c *ReleaseClosure) { c.TrustPolicyDigest = testOldDigest }},
		{name: "source smoke claims pass", mutate: func(c *ReleaseClosure) {
			c.PublishedSmoke = ClosureCheck{Status: "PASS", EvidenceRef: "https://evidence.example/smoke", EvidenceDigest: testDigest}
		}},
		{name: "released monitoring failed", mutate: func(c *ReleaseClosure) { c.Monitoring.Status = "FAIL" }},
		{name: "zero duration monitoring", mutate: func(c *ReleaseClosure) { c.Monitoring.EndedAt = c.Monitoring.StartedAt }},
		{name: "released with rollback", mutate: func(c *ReleaseClosure) {
			c.Rollback = &ClosureCheck{Status: "PASS", EvidenceRef: "https://evidence.example/rollback", EvidenceDigest: testDigest}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := closure
			tt.mutate(&candidate)
			if err := validateClosure(rawManifest, &manifest, &candidate); err == nil {
				t.Fatal("validateClosure accepted unbound or contradictory closure")
			}
		})
	}

	closure.Outcome = "ROLLED_BACK"
	closure.OutcomeReason = "monitoring threshold exceeded"
	closure.Monitoring.Status = "FAIL"
	closure.Rollback = &ClosureCheck{Status: "PASS", EvidenceRef: "https://evidence.example/aegis/closure/rollback.json", EvidenceDigest: testDigest}
	if err := validateClosure(rawManifest, &manifest, &closure); err != nil {
		t.Fatalf("validateClosure rejected truthful rollback closure: %v", err)
	}
	closure.Rollback.Status = "FAIL"
	if err := validateClosure(rawManifest, &manifest, &closure); err == nil {
		t.Fatal("validateClosure accepted a failed rollback as a closed rollback outcome")
	}
}

func TestRunValidatesClosureSchemaWithoutClaimingReleaseApproval(t *testing.T) {
	manifest := validManifest()
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	rawClosure, err := json.Marshal(validClosure(rawManifest, manifest))
	if err != nil {
		t.Fatalf("Marshal closure: %v", err)
	}
	root := t.TempDir()
	manifestPath := filepath.Join(root, "manifest.json")
	closurePath := filepath.Join(root, "closure.json")
	if err := os.WriteFile(manifestPath, rawManifest, 0o600); err != nil {
		t.Fatalf("WriteFile manifest: %v", err)
	}
	if err := os.WriteFile(closurePath, rawClosure, 0o600); err != nil {
		t.Fatalf("WriteFile closure: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"-manifest", manifestPath, "-closure", closurePath, "-schema-only"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "CLOSURE_SCHEMA_VALID_NOT_RELEASE_APPROVED") ||
		strings.HasPrefix(stdout.String(), "VALID ") {
		t.Fatalf("closure schema result: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func validClosure(rawManifest []byte, manifest Manifest) ReleaseClosure {
	digest := sha256.Sum256(rawManifest)
	return ReleaseClosure{
		SchemaVersion:     "aegis.release-closure/v1",
		ReleaseVersion:    manifest.ReleaseVersion,
		CreatedAt:         "2026-08-20T13:40:00Z",
		ManifestURI:       "https://evidence.example/aegis/manifest.json",
		ManifestDigest:    "sha256:" + hex.EncodeToString(digest[:]),
		ApprovalRef:       "https://evidence.example/aegis/approval.json",
		ApprovalDigest:    testOldDigest,
		TrustPolicyURI:    manifest.ReleaseApprovalPolicy.TrustPolicyURI,
		TrustPolicyDigest: manifest.ReleaseApprovalPolicy.TrustPolicyDigest,
		VerifierURI:       manifest.ReleaseApprovalPolicy.VerifierURI,
		VerifierDigest:    manifest.ReleaseApprovalPolicy.VerifierDigest,
		CandidateSHA:      manifest.CandidateSHA,
		TagName:           manifest.TagName,
		TagObjectSHA:      manifest.TagObjectSHA,
		TagTargetSHA:      manifest.TagTargetSHA,
		ArtifactScope:     manifest.ArtifactScope.Decision,
		ArtifactDigests:   artifactDigestOrder(manifest.Artifacts),
		RemoteVerification: ClosureCheck{
			Status: "PASS", EvidenceRef: "https://evidence.example/aegis/closure/remote.json", EvidenceDigest: testDigest,
		},
		PublishedSmoke: ClosureCheck{Status: "NOT_APPLICABLE", Justification: "source tag only publishes no executable artifact"},
		Monitoring: ClosureMonitoring{
			StartedAt: "2026-08-20T12:50:00Z", EndedAt: "2026-08-20T13:30:00Z", Status: "PASS",
			EvidenceRef: "https://evidence.example/aegis/closure/monitoring.json", EvidenceDigest: testDigest,
		},
		Outcome:       "RELEASED",
		OutcomeReason: "all post-publication checks passed",
	}
}

func testBinaryArtifact(platform, reference, digest, suffix, attestationDigest string) Artifact {
	return Artifact{
		Type:        "binary",
		Platform:    platform,
		Reference:   reference,
		Digest:      digest,
		SourceSHA:   testCandidateSHA,
		EmbeddedSHA: testCandidateSHA,
		Toolchain:   "go1.26.6",
		SBOM: Attestation{
			Status: "present", Reference: "release://sbom-" + suffix, Digest: attestationDigest,
		},
		Signature: Attestation{
			Status: "present", Reference: "release://signature-" + suffix, Digest: attestationDigest,
		},
		Provenance: Attestation{
			Status: "present", Reference: "release://provenance-" + suffix, Digest: attestationDigest,
		},
	}
}

func testContainerArtifact(platform, reference, digest, suffix, attestationDigest string) Artifact {
	artifact := testBinaryArtifact(platform, reference, digest, suffix, attestationDigest)
	artifact.Type = "container"
	return artifact
}

type rollbackReportFixture struct {
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

func validManifestWithRollbackReportV3(t *testing.T) []byte {
	t.Helper()
	manifest := validManifest()
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	return raw
}

func replaceManifestBytes(t *testing.T, raw []byte, oldValue, newValue string, expectedCount int) []byte {
	t.Helper()
	if count := bytes.Count(raw, []byte(oldValue)); count != expectedCount {
		t.Fatalf("manifest fixture replacement count = %d, want %d for %q", count, expectedCount, oldValue)
	}
	return bytes.ReplaceAll(raw, []byte(oldValue), []byte(newValue))
}

func bindRollbackReportFixture(manifest *Manifest) {
	report := rollbackReportFixture{
		SchemaVersion:         3,
		Result:                "PASS",
		EvidenceClass:         "FINAL_CANDIDATE",
		WorktreeClean:         true,
		RunID:                 manifest.Rollback.RunID,
		ContainmentNonce:      manifest.Rollback.ContainmentNonce,
		StartedAt:             manifest.Rollback.StartedAt,
		EndedAt:               manifest.Rollback.EndedAt,
		RunnerBinarySHA256:    manifest.Rollback.RunnerBinarySHA256,
		CandidateSHA:          manifest.Rollback.CandidateSHA,
		RollbackSourceSHA:     manifest.Rollback.OldTagSHA,
		CandidateBinarySHA256: strings.TrimPrefix(manifest.Rollback.CandidateBinaryDigest, "sha256:"),
		RollbackBinarySHA256:  strings.TrimPrefix(manifest.Rollback.OldBinaryDigest, "sha256:"),
		InputLockDigest:       strings.TrimPrefix(manifest.Rollback.InputLockDigest, "sha256:"),
		Migration:             "legacy_file_store_to_v2_strict_pass",
		CurrentSmoke:          "health_auth_kms_tls_provider_200_pass",
		Rollback:              "encrypted_backup_restore_v0.2.0_health_auth_kms_tls_provider_200_pass",
	}
	var raw bytes.Buffer
	encoder := json.NewEncoder(&raw)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		panic("encode rollback report fixture: " + err.Error())
	}
	digest := sha256.Sum256(raw.Bytes())
	manifest.Rollback.EvidenceDigest = "sha256:" + hex.EncodeToString(digest[:])
	testGate(manifest, "rollback-drill").EvidenceDigest = manifest.Rollback.EvidenceDigest
}

func testGate(manifest *Manifest, name string) *Gate {
	for index := range manifest.Gates {
		if manifest.Gates[index].Name == name {
			return &manifest.Gates[index]
		}
	}
	panic("missing test gate: " + name)
}

func bindBuiltArtifacts(manifest *Manifest) {
	canonicalSummary := Attestation{
		Status:        "not_applicable",
		Justification: "supply-chain evidence is recorded per artifact",
	}
	manifest.ArtifactScope.SBOM = canonicalSummary
	manifest.ArtifactScope.Signature = canonicalSummary
	manifest.ArtifactScope.Provenance = canonicalSummary

	ordered := artifactDigestOrder(manifest.Artifacts)
	var binaries, containers []string
	attestationReferences := make(map[string][]string, 3)
	attestationDigests := make(map[string][]string, 3)
	for _, artifact := range manifest.Artifacts {
		switch artifact.Type {
		case "binary":
			binaries = append(binaries, artifact.Digest)
		case "container":
			containers = append(containers, artifact.Digest)
		}
		attestationReferences["sbom-verify"] = append(attestationReferences["sbom-verify"], artifact.SBOM.Reference)
		attestationDigests["sbom-verify"] = append(attestationDigests["sbom-verify"], artifact.SBOM.Digest)
		attestationReferences["artifact-signature-verify"] = append(attestationReferences["artifact-signature-verify"], artifact.Signature.Reference)
		attestationDigests["artifact-signature-verify"] = append(attestationDigests["artifact-signature-verify"], artifact.Signature.Digest)
		attestationReferences["provenance-verify"] = append(attestationReferences["provenance-verify"], artifact.Provenance.Reference)
		attestationDigests["provenance-verify"] = append(attestationDigests["provenance-verify"], artifact.Provenance.Digest)
	}
	manifest.QA.SUTDigests = append([]string(nil), ordered...)
	for index := range manifest.Gates {
		switch manifest.Gates[index].Name {
		case "govulncheck-binary":
			manifest.Gates[index].ArtifactDigests = append([]string(nil), binaries...)
		case "ceo-docker-smoke":
			manifest.Gates[index].ArtifactDigests = append([]string(nil), containers...)
		case "independent-qa":
			manifest.Gates[index].ArtifactDigests = append([]string(nil), ordered...)
		}
	}
	for _, name := range []string{"sbom-verify", "artifact-signature-verify", "provenance-verify"} {
		manifest.Gates = append(manifest.Gates, Gate{
			Name:                  name,
			Status:                "PASS",
			Timestamp:             "2026-08-20T12:11:00Z",
			ToolVersion:           "release-tool-v1",
			RunURL:                "https://evidence.example/aegis/runs/" + name,
			RunID:                 "content-addressed-" + name,
			EvidenceRef:           "https://evidence.example/aegis/gates/" + name,
			EvidenceDigest:        testDigest,
			CandidateSHA:          testCandidateSHA,
			ArtifactDigests:       append([]string(nil), ordered...),
			AttestationReferences: append([]string(nil), attestationReferences[name]...),
			AttestationDigests:    append([]string(nil), attestationDigests[name]...),
		})
	}
}

func validManifest() Manifest {
	notApplicable := Attestation{Status: "not_applicable", Justification: "source tag only publishes no built artifact"}
	gates := make([]Gate, 0, len(requiredFinalGates))
	for _, name := range requiredFinalGates {
		timestamp := "2026-08-20T12:10:00Z"
		runURL := "https://evidence.example/aegis/runs/" + name
		runID := "content-addressed-" + name
		evidenceRef := "https://evidence.example/aegis/gates/" + name
		if name == "independent-qa" {
			runURL = "https://github.com/example/aegis-independent-qa/actions/runs/1"
			runID = "1"
			evidenceRef = "https://evidence.example/aegis/qa/evidence-bundle.json"
		}
		if name == "rollback-drill" {
			timestamp = testRollbackEnd
			runID = testRollbackRunID
			evidenceRef = "https://evidence.example/aegis/rollback/report.json"
		}
		switch name {
		case "security-review":
			timestamp = "2026-08-20T12:20:00Z"
		case "runtime-architecture-review":
			timestamp = "2026-08-20T12:21:00Z"
		case "quality-review":
			timestamp = "2026-08-20T12:22:00Z"
		}
		gates = append(gates, Gate{
			Name:           name,
			Status:         "PASS",
			Timestamp:      timestamp,
			ToolVersion:    "go1.26.6",
			RunURL:         runURL,
			RunID:          runID,
			EvidenceRef:    evidenceRef,
			EvidenceDigest: testDigest,
			CandidateSHA:   testCandidateSHA,
		})
	}
	manifest := Manifest{
		SchemaVersion:  "aegis.release-evidence/v1",
		ReleaseVersion: "v0.2.1",
		CreatedAt:      "2026-08-20T12:40:00Z",
		CandidateSHA:   testCandidateSHA,
		CandidateTree:  testTreeSHA,
		WorktreeClean:  true,
		EvidenceMode:   "FINAL",
		TagName:        "v0.2.1",
		TagObjectSHA:   testTagObjectSHA,
		TagTargetSHA:   testCandidateSHA,
		ArtifactScope: ArtifactScope{
			Decision:   "source_tag_only",
			Rationale:  "standalone validation source release",
			SBOM:       notApplicable,
			Signature:  notApplicable,
			Provenance: notApplicable,
		},
		Artifacts: []Artifact{},
		Gates:     gates,
		QA: QA{
			Repository:           "https://github.com/example/aegis-independent-qa",
			Revision:             "5555555555555555555555555555555555555555",
			SUTSHA:               testCandidateSHA,
			SUTBinaryDigest:      testDigest,
			SUTDigests:           []string{},
			RunURL:               "https://github.com/example/aegis-independent-qa/actions/runs/1",
			RunID:                "1",
			EvidenceRef:          "https://evidence.example/aegis/qa/evidence-bundle.json",
			EvidenceBundleDigest: testDigest,
		},
		ContainerSmoke: &ContainerSmoke{
			ArtifactBinding:  "PREPUBLICATION_CANDIDATE_NOT_PUBLISHED",
			Timestamp:        "2026-08-20T12:10:00Z",
			RunURL:           "https://evidence.example/aegis/runs/ceo-docker-smoke",
			RunID:            "content-addressed-ceo-docker-smoke",
			EvidenceRef:      "https://evidence.example/aegis/gates/ceo-docker-smoke",
			EvidenceDigest:   testDigest,
			ImageID:          "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			ImageDigest:      "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			SourceSHA:        testCandidateSHA,
			OS:               "linux",
			Architecture:     "arm64",
			RuntimeUser:      "nonroot:nonroot",
			ReadOnlyRoot:     true,
			HealthStatus:     "PASS",
			AuthStatus:       "PASS",
			RevocationStatus: "PASS",
			CleanupStatus:    "PASS",
		},
		Reviewers: []Reviewer{
			{
				Identity: "security-review", Role: "technical-security", Decision: "ACCEPT", Timestamp: "2026-08-20T12:20:00Z",
				GateName: "security-review", RunURL: "https://evidence.example/aegis/runs/security-review",
				RunID: "content-addressed-security-review", EvidenceRef: "https://evidence.example/aegis/gates/security-review", EvidenceDigest: testDigest,
			},
			{
				Identity: "architecture-review", Role: "runtime-architecture", Decision: "ACCEPT", Timestamp: "2026-08-20T12:21:00Z",
				GateName: "runtime-architecture-review", RunURL: "https://evidence.example/aegis/runs/runtime-architecture-review",
				RunID: "content-addressed-runtime-architecture-review", EvidenceRef: "https://evidence.example/aegis/gates/runtime-architecture-review", EvidenceDigest: testDigest,
			},
			{
				Identity: "quality-review", Role: "quality-release", Decision: "ACCEPT", Timestamp: "2026-08-20T12:22:00Z",
				GateName: "quality-review", RunURL: "https://evidence.example/aegis/runs/quality-review",
				RunID: "content-addressed-quality-review", EvidenceRef: "https://evidence.example/aegis/gates/quality-review", EvidenceDigest: testDigest,
			},
		},
		ReleaseApprovalPolicy: ReleaseApprovalPolicy{
			RequiredRole: "independent-release-approver", RequiredKeyID: testApproverKeyID,
			MinimumApprovals: 1, MustBeIndependent: true, DetachedApproval: true,
			TrustPolicyURI: "https://evidence.example/aegis/trust-policy-v1.json", TrustPolicyDigest: testDigest,
			VerifierURI: "https://evidence.example/aegis/release-verifier-v1", VerifierDigest: testOldDigest,
		},
		Rollback: RollbackEvidence{
			Status:                    "PASS",
			Timestamp:                 testRollbackEnd,
			RunID:                     testRollbackRunID,
			ContainmentNonce:          testRollbackNonce,
			StartedAt:                 testRollbackStart,
			EndedAt:                   testRollbackEnd,
			RunnerBinarySHA256:        testRunnerSHA256,
			EvidenceRef:               "https://evidence.example/aegis/rollback/report.json",
			EvidenceDigest:            testDigest,
			InputLockRef:              "https://evidence.example/aegis/rollback/input-lock.json",
			InputLockDigest:           testOldDigest,
			ContainmentProfile:        "dedicated-linux-cgroup-v2-pid-namespace-v1",
			ContainmentEvidenceRef:    "https://evidence.example/aegis/rollback/containment.json",
			ContainmentEvidenceDigest: testDigest,
			CandidateSHA:              testCandidateSHA,
			CandidateBinaryDigest:     testDigest,
			OldTag:                    "v0.2.0",
			OldTagSHA:                 testOldTagSHA,
			OldBinaryDigest:           testOldDigest,
		},
		AcceptedRisks:      []Finding{},
		OpenFindings:       []Finding{},
		UnverifiedSurfaces: []string{},
		ManifestID:         "aegis-v0.2.1-final-1",
		RetentionPolicy:    "immutable for at least the supported release lifetime",
	}
	bindRollbackReportFixture(&manifest)
	return manifest
}
