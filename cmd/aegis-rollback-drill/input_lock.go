package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yknothing/AegisLLM/internal/utils"
)

const (
	rollbackInputLockSchema   = "aegis.rollback-input-lock/v2"
	maxRollbackInputLockBytes = 64 << 10
)

type rollbackInputLock struct {
	Schema                    string
	RunID                     string
	ContainmentNonce          string
	CandidateSHA              string
	CandidateBinarySHA256     string
	CandidateProvenanceRef    string
	CandidateProvenanceSHA256 string
	RollbackTag               string
	RollbackSHA               string
	RollbackBinarySHA256      string
	RollbackProvenanceRef     string
	RollbackProvenanceSHA256  string
	RunnerBinarySHA256        string
	RunnerProvenanceRef       string
	RunnerProvenanceSHA256    string
	TrustPolicyURI            string
	TrustPolicySHA256         string
	BuilderIdentity           string
	CreatedAt                 string
}

var rollbackInputLockKeys = map[string]struct{}{
	"schema":                      {},
	"run_id":                      {},
	"containment_nonce":           {},
	"candidate_sha":               {},
	"candidate_binary_sha256":     {},
	"candidate_provenance_ref":    {},
	"candidate_provenance_sha256": {},
	"rollback_tag":                {},
	"rollback_sha":                {},
	"rollback_binary_sha256":      {},
	"rollback_provenance_ref":     {},
	"rollback_provenance_sha256":  {},
	"runner_binary_sha256":        {},
	"runner_provenance_ref":       {},
	"runner_provenance_sha256":    {},
	"trust_policy_uri":            {},
	"trust_policy_sha256":         {},
	"builder_identity":            {},
	"created_at":                  {},
}

func loadRollbackInputLock(path, expectedDigest string) (rollbackInputLock, string, error) {
	if !fullSHA256.MatchString(expectedDigest) {
		return rollbackInputLock{}, "", errors.New("input lock expected digest is invalid")
	}
	data, err := readOwnerOnlyFile(path, maxRollbackInputLockBytes)
	if err != nil {
		return rollbackInputLock{}, "", err
	}
	defer utils.MemZero(data)
	digestBytes := sha256.Sum256(data)
	digest := hex.EncodeToString(digestBytes[:])
	if !digestMatches(digest, expectedDigest) {
		return rollbackInputLock{}, "", errors.New("input lock digest mismatch")
	}
	lock, err := parseRollbackInputLock(data)
	if err != nil {
		return rollbackInputLock{}, "", err
	}
	return lock, digest, nil
}

func parseRollbackInputLock(data []byte) (rollbackInputLock, error) {
	if !utf8.Valid(data) {
		return rollbackInputLock{}, errors.New("input lock is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return rollbackInputLock{}, errors.New("input lock must be one JSON object")
	}
	values := make(map[string]string, len(rollbackInputLockKeys))
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return rollbackInputLock{}, errors.New("input lock member is invalid")
		}
		key, ok := keyToken.(string)
		if !ok {
			return rollbackInputLock{}, errors.New("input lock member name is invalid")
		}
		if _, allowed := rollbackInputLockKeys[key]; !allowed {
			return rollbackInputLock{}, errors.New("input lock contains an unknown or case-mismatched member")
		}
		if _, duplicate := values[key]; duplicate {
			return rollbackInputLock{}, errors.New("input lock contains a duplicate member")
		}
		valueToken, err := decoder.Token()
		if err != nil {
			return rollbackInputLock{}, errors.New("input lock member value is invalid")
		}
		value, ok := valueToken.(string)
		if !ok {
			return rollbackInputLock{}, errors.New("input lock members must be strings")
		}
		values[key] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return rollbackInputLock{}, errors.New("input lock object is incomplete")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return rollbackInputLock{}, errors.New("input lock has trailing data")
	}
	if len(values) != len(rollbackInputLockKeys) {
		return rollbackInputLock{}, errors.New("input lock is missing required members")
	}
	lock := rollbackInputLock{
		Schema:                    values["schema"],
		RunID:                     values["run_id"],
		ContainmentNonce:          values["containment_nonce"],
		CandidateSHA:              values["candidate_sha"],
		CandidateBinarySHA256:     values["candidate_binary_sha256"],
		CandidateProvenanceRef:    values["candidate_provenance_ref"],
		CandidateProvenanceSHA256: values["candidate_provenance_sha256"],
		RollbackTag:               values["rollback_tag"],
		RollbackSHA:               values["rollback_sha"],
		RollbackBinarySHA256:      values["rollback_binary_sha256"],
		RollbackProvenanceRef:     values["rollback_provenance_ref"],
		RollbackProvenanceSHA256:  values["rollback_provenance_sha256"],
		RunnerBinarySHA256:        values["runner_binary_sha256"],
		RunnerProvenanceRef:       values["runner_provenance_ref"],
		RunnerProvenanceSHA256:    values["runner_provenance_sha256"],
		TrustPolicyURI:            values["trust_policy_uri"],
		TrustPolicySHA256:         values["trust_policy_sha256"],
		BuilderIdentity:           values["builder_identity"],
		CreatedAt:                 values["created_at"],
	}
	if err := validateRollbackInputLock(lock); err != nil {
		return rollbackInputLock{}, err
	}
	return lock, nil
}

func validateRollbackInputLock(lock rollbackInputLock) error {
	if lock.Schema != rollbackInputLockSchema || !fullSHA.MatchString(lock.CandidateSHA) || lock.CandidateSHA == rollbackV020SHA ||
		lock.RollbackTag != "v0.2.0" || lock.RollbackSHA != rollbackV020SHA {
		return errors.New("input lock release identity is invalid")
	}
	if !canonicalRunID.MatchString(lock.RunID) || !fullSHA256.MatchString(lock.ContainmentNonce) ||
		lock.ContainmentNonce == strings.Repeat("0", sha256.Size*2) {
		return errors.New("input lock run or containment identity is invalid")
	}
	for _, digest := range []string{
		lock.CandidateBinarySHA256,
		lock.CandidateProvenanceSHA256,
		lock.RollbackBinarySHA256,
		lock.RollbackProvenanceSHA256,
		lock.RunnerBinarySHA256,
		lock.RunnerProvenanceSHA256,
		lock.TrustPolicySHA256,
	} {
		if !fullSHA256.MatchString(digest) {
			return errors.New("input lock contains an invalid digest")
		}
	}
	for _, reference := range []string{
		lock.CandidateProvenanceRef,
		lock.RollbackProvenanceRef,
		lock.RunnerProvenanceRef,
		lock.BuilderIdentity,
	} {
		if err := validateAbsoluteReference(reference, false); err != nil {
			return err
		}
	}
	if err := validateAbsoluteReference(lock.TrustPolicyURI, true); err != nil {
		return err
	}
	createdAt, err := time.Parse(time.RFC3339Nano, lock.CreatedAt)
	if err != nil || !strings.HasSuffix(lock.CreatedAt, "Z") || createdAt.Format(time.RFC3339Nano) != lock.CreatedAt {
		return errors.New("input lock created_at must be canonical UTC RFC3339")
	}
	return nil
}

func validateAbsoluteReference(reference string, requireHTTPS bool) error {
	if reference == "" || len(reference) > 2048 {
		return errors.New("input lock reference is invalid")
	}
	for index := 0; index < len(reference); index++ {
		if reference[index] < 0x21 || reference[index] > 0x7e {
			return errors.New("input lock reference is invalid")
		}
	}
	parsed, err := url.Parse(reference)
	if err != nil || !parsed.IsAbs() || parsed.User != nil || parsed.Fragment != "" || strings.Contains(reference, "#") {
		return errors.New("input lock reference is invalid")
	}
	if requireHTTPS {
		if parsed.Scheme != "https" || parsed.Hostname() == "" {
			return errors.New("input lock trust policy URI must use safe HTTPS authority")
		}
		return nil
	}
	switch parsed.Scheme {
	case "https":
		if parsed.Hostname() == "" {
			return errors.New("input lock HTTPS reference hostname is missing")
		}
	case "urn":
		if parsed.Opaque == "" {
			return errors.New("input lock URN reference opaque value is missing")
		}
	default:
		return errors.New("input lock reference scheme is not allowed")
	}
	return nil
}
