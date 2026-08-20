// Package middleware - redaction.go implements PII (Personally Identifiable Information) redaction.
//
// DESIGN:
//   - Scans request bodies for sensitive patterns before forwarding to providers
//   - Configurable rules: regex patterns for emails, phone numbers, SSNs, etc.
//   - Can operate in detect-only, redact, or block mode
//   - Bounds semantic traversal depth, value count, object width, and output
//
// SECURITY:
//   - Prevents accidental PII leakage to third-party LLM providers
//   - Supports compliance requirements (GDPR, CCPA, HIPAA)
//   - Redaction happens BEFORE the request leaves the gateway
//   - Original content is never logged
package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/yknothing/AegisLLM/internal/config"
	"github.com/yknothing/AegisLLM/internal/server"
	"github.com/yknothing/AegisLLM/internal/utils"
)

// RedactionMode determines how detected PII is handled.
type RedactionMode string

const (
	// ModeDetect validates and scans but does not modify or reject the request.
	ModeDetect RedactionMode = "detect"
	// ModeRedact replaces detected PII with placeholder text.
	ModeRedact RedactionMode = "redact"
	// ModeBlock rejects the request entirely if PII is detected.
	ModeBlock RedactionMode = "block"
)

// RedactionRule defines a pattern to detect and optionally redact.
type RedactionRule struct {
	Name        string         // Human-readable rule name (e.g., "email")
	Pattern     *regexp.Regexp // Compiled regex pattern
	Replacement string         // Replacement text (e.g., "[EMAIL_REDACTED]")
	Enabled     bool
}

// RedactionConfig configures the PII redaction middleware.
type RedactionConfig struct {
	Mode               RedactionMode
	Rules              []RedactionRule
	MaxRequestBodySize int64
}

// DefaultRedactionRules returns a set of common PII detection patterns.
func DefaultRedactionRules() []RedactionRule {
	return []RedactionRule{
		{
			Name:        "email",
			Pattern:     regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
			Replacement: "[EMAIL_REDACTED]",
			Enabled:     true,
		},
		{
			Name:        "phone_us",
			Pattern:     regexp.MustCompile(`(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`),
			Replacement: "[PHONE_REDACTED]",
			Enabled:     true,
		},
		{
			Name:        "ssn",
			Pattern:     regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			Replacement: "[SSN_REDACTED]",
			Enabled:     true,
		},
		{
			Name:        "credit_card",
			Pattern:     regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`),
			Replacement: "[CC_REDACTED]",
			Enabled:     true,
		},
		{
			Name:        "api_key_pattern",
			Pattern:     regexp.MustCompile(`(sk-[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16})`),
			Replacement: "[KEY_REDACTED]",
			Enabled:     true,
		},
		{
			Name:        "china_id",
			Pattern:     regexp.MustCompile(`\b\d{17}[\dXx]\b`),
			Replacement: "[ID_REDACTED]",
			Enabled:     true,
		},
		{
			Name:        "china_phone",
			Pattern:     regexp.MustCompile(`\b1[3-9]\d{9}\b`),
			Replacement: "[PHONE_REDACTED]",
			Enabled:     true,
		},
	}
}

// PIIRedaction creates the PII redaction middleware.
func PIIRedaction(cfg RedactionConfig) server.Middleware {
	scanner := newPIIScanner(cfg)

	return func(ctx *server.RequestContext, next func()) {
		bodyLimit := cfg.MaxRequestBodySize
		if bodyLimit <= 0 {
			bodyLimit = defaultMaxRequestBodySize
		}
		semanticBodyLimit := min(bodyLimit, int64(maxSemanticRequestBodyBytes))
		body, err := readRequestBody(ctx, semanticBodyLimit)
		if errors.Is(err, errRequestBodyTooLarge) {
			ctx.Abort(http.StatusRequestEntityTooLarge, []byte(`{"error":{"message":"request body too large","type":"invalid_request_error"}}`))
			return
		}
		if err != nil {
			ctx.Abort(http.StatusBadRequest, []byte(`{"error":{"message":"invalid request body","type":"invalid_request_error"}}`))
			return
		}

		// A prior middleware or test may have populated RequestBody under a wider
		// limit. Re-check it before semantic decoding so the working-set envelope
		// does not depend on middleware order.
		if int64(len(body)) > semanticBodyLimit {
			ctx.Abort(http.StatusRequestEntityTooLarge, []byte(`{"error":{"message":"request body too large","type":"invalid_request_error"}}`))
			return
		}
		processedBody, foundPII, err := scanner.ProcessJSON(body, semanticBodyLimit)
		if errors.Is(err, errSemanticJSONLimit) {
			ctx.Abort(http.StatusRequestEntityTooLarge, []byte(`{"error":{"message":"request body too large","type":"invalid_request_error"}}`))
			return
		}
		if errors.Is(err, errSemanticPIIBlocked) {
			ctx.Abort(http.StatusBadRequest, blockErrorJSON())
			return
		}
		if err != nil {
			ctx.Abort(http.StatusBadRequest, []byte(`{"error":{"message":"invalid request body","type":"invalid_request_error"}}`))
			return
		}

		switch scanner.mode {
		case ModeDetect:
			next()
		case ModeBlock:
			if foundPII {
				ctx.Abort(http.StatusBadRequest, blockErrorJSON())
				return
			}
			next()
		default:
			replaceRequestBody(ctx, processedBody)
			next()
		}
	}
}

const (
	// Semantic processing defines the same 4 MiB outer envelope enforced by
	// configuration. encoding/json plus a canonical output and decoded strings
	// can otherwise retain several body-sized allocations per concurrent request.
	// The bounds below limit caller-owned
	// input to 4 MiB, any decoded scalar or joined message text to 512 KiB, one
	// buffered content array to 1 MiB, and retained canonical output capacity to
	// 4 MiB. Output grows from
	// at most 32 KiB and an old allocation is cleared on each resize; even during
	// a resize, old plus new output capacity cannot exceed 8 MiB. These major
	// buffers are therefore bounded independently inside the outer request cap.
	maxSemanticRequestBodyBytes  = int(config.MaxRequestBodySizeLimit)
	maxSemanticJSONStringBytes   = 512 << 10
	maxSemanticContentPartBytes  = 1 << 20
	maxSemanticContentArrayBytes = 1 << 20
	maxSemanticJoinedTextBytes   = 512 << 10
	maxSemanticContentParts      = 4_096
	maxSemanticRedactionMatches  = 1_024
	maxSemanticNumericPIIDigits  = 32
	maxSemanticJSONDepth         = 64
	maxSemanticJSONValues        = 100_000
	maxSemanticJSONObjectMembers = 4_096
)

var (
	errInvalidSemanticJSON = errors.New("invalid JSON request body")
	errSemanticJSONLimit   = errors.New("semantic JSON complexity limit exceeded")
	errSemanticPIIBlocked  = errors.New("PII in a non-redactable JSON position")
)

type semanticJSONProcessor struct {
	decoder             *json.Decoder
	output              *boundedSemanticOutput
	outputMax           int64
	mode                RedactionMode
	rules               []RedactionRule
	contentTextOverride *string
	values              int
	foundPII            bool
}

type boundedSemanticOutput struct {
	data []byte
	max  int
}

func newBoundedSemanticOutput(maxBytes int64) *boundedSemanticOutput {
	maxInt := int(maxBytes)
	return &boundedSemanticOutput{
		data: make([]byte, 0, min(maxInt, 32<<10)),
		max:  maxInt,
	}
}

func (o *boundedSemanticOutput) append(value []byte) error {
	if len(value) > o.max-len(o.data) {
		return errSemanticJSONLimit
	}
	needed := len(o.data) + len(value)
	if needed > cap(o.data) {
		newCapacity := max(needed, cap(o.data)*2)
		newCapacity = min(newCapacity, o.max)
		grown := make([]byte, len(o.data), newCapacity)
		copy(grown, o.data)
		utils.MemZero(o.data)
		o.data = grown
	}
	o.data = append(o.data, value...)
	return nil
}

func (o *boundedSemanticOutput) bytes() []byte {
	return o.data
}

func (o *boundedSemanticOutput) len() int {
	return len(o.data)
}

func (o *boundedSemanticOutput) zero() {
	utils.MemZero(o.data)
}

type semanticValueContext uint8

const (
	semanticContextGeneric semanticValueContext = iota
	semanticContextRoot
	semanticContextMessages
	semanticContextMessage
	semanticContextMessageContent
	semanticContextContentPart
)

type semanticContentPart struct {
	raw          []byte
	isText       bool
	text         string
	textOverride string
}

type redactionSpan struct {
	start       int
	end         int
	replacement string
	matchWidth  int
}

// ProcessJSON validates exactly one JSON value and processes it token by token.
// Redact mode emits one canonical bounded body without retaining a decoded tree;
// detect mode preserves the caller-owned body. Duplicate members, ambiguous
// model/stream aliases, excessive structure, and non-redactable PII fail closed.
func (s *piiScanner) ProcessJSON(body []byte, outputMax int64) ([]byte, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(body) > maxSemanticRequestBodyBytes || outputMax <= 0 {
		return nil, false, errSemanticJSONLimit
	}
	outputMax = min(outputMax, int64(maxSemanticRequestBodyBytes))

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	processor := semanticJSONProcessor{
		decoder:   decoder,
		outputMax: outputMax,
		mode:      s.mode,
		rules:     s.rules,
	}
	if s.mode != ModeDetect && s.mode != ModeBlock {
		processor.output = newBoundedSemanticOutput(outputMax)
	}
	if err := processor.processValue(0, semanticContextRoot); err != nil {
		processor.zeroOutput()
		return nil, processor.foundPII, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		processor.zeroOutput()
		return nil, processor.foundPII, errInvalidSemanticJSON
	}
	if processor.output == nil {
		return nil, processor.foundPII, nil
	}
	return processor.output.bytes(), processor.foundPII, nil
}

func (p *semanticJSONProcessor) processValue(depth int, context semanticValueContext) error {
	if depth > maxSemanticJSONDepth {
		return errSemanticJSONLimit
	}
	p.values++
	if p.values > maxSemanticJSONValues {
		return errSemanticJSONLimit
	}

	token, err := p.decoder.Token()
	if err != nil {
		return errInvalidSemanticJSON
	}
	delim, isDelim := token.(json.Delim)
	if isDelim {
		switch delim {
		case '{':
			return p.processObject(depth, context)
		case '[':
			if context == semanticContextMessageContent {
				return p.processContentPartsArray(depth)
			}
			return p.processArray(depth, context)
		default:
			return errInvalidSemanticJSON
		}
	}

	switch value := token.(type) {
	case string:
		if len(value) > maxSemanticJSONStringBytes {
			return errSemanticJSONLimit
		}
		return p.processStringValue(value)
	case json.Number:
		rawNumber := value.String()
		if len(rawNumber) > maxSemanticJSONStringBytes {
			return errSemanticJSONLimit
		}
		matched := rulesMatchString(rawNumber, p.rules)
		if !matched {
			canonicalInteger, candidate, err := canonicalNumericPIICandidate(rawNumber)
			if err != nil {
				return err
			}
			matched = candidate && rulesMatchString(canonicalInteger, p.rules)
		}
		if matched {
			p.foundPII = true
			if p.mode != ModeDetect {
				return errSemanticPIIBlocked
			}
		}
		return p.writeString(rawNumber)
	case bool:
		if value {
			return p.writeString("true")
		}
		return p.writeString("false")
	case nil:
		return p.writeString("null")
	default:
		return errInvalidSemanticJSON
	}
}

// canonicalNumericPIICandidate returns a short exact-integer rendering of a
// JSON number so scientific/fractional spelling cannot hide phone or card
// digits from lexical rules. Large numeric values remain valid JSON but are not
// expanded: the raw spelling has already been scanned and only PII-sized exact
// integers are useful secondary candidates.
func canonicalNumericPIICandidate(raw string) (string, bool, error) {
	negative := strings.HasPrefix(raw, "-")
	if negative {
		raw = raw[1:]
	}
	mantissa := raw
	exponent := int64(0)
	if index := strings.IndexAny(raw, "eE"); index >= 0 {
		mantissa = raw[:index]
		parsed, err := strconv.ParseInt(raw[index+1:], 10, 64)
		if err != nil || parsed > maxSemanticJSONStringBytes || parsed < -maxSemanticJSONStringBytes {
			return "", false, errSemanticJSONLimit
		}
		exponent = parsed
	}

	integerDigits := len(mantissa)
	digits := mantissa
	if dot := strings.IndexByte(mantissa, '.'); dot >= 0 {
		integerDigits = dot
		digits = mantissa[:dot] + mantissa[dot+1:]
	}
	decimalPosition := int64(integerDigits) + exponent
	if decimalPosition <= 0 {
		if strings.Trim(digits, "0") == "" {
			return "0", true, nil
		}
		return "", false, nil
	}

	zerosToAppend := int64(0)
	if decimalPosition < int64(len(digits)) {
		if strings.Trim(digits[decimalPosition:], "0") != "" {
			return "", false, nil
		}
		digits = digits[:decimalPosition]
	} else {
		zerosToAppend = decimalPosition - int64(len(digits))
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return "0", true, nil
	}
	if int64(len(digits))+zerosToAppend > maxSemanticNumericPIIDigits {
		return "", false, nil
	}
	if zerosToAppend > 0 {
		digits += strings.Repeat("0", int(zerosToAppend))
	}
	if negative {
		digits = "-" + digits
	}
	return digits, true, nil
}

func (p *semanticJSONProcessor) processObject(depth int, context semanticValueContext) error {
	if err := p.writeString("{"); err != nil {
		return err
	}
	seen := make(map[string]struct{})
	members := 0
	for p.decoder.More() {
		members++
		if members > maxSemanticJSONObjectMembers {
			return errSemanticJSONLimit
		}
		keyToken, err := p.decoder.Token()
		if err != nil {
			return errInvalidSemanticJSON
		}
		key, ok := keyToken.(string)
		if !ok {
			return errInvalidSemanticJSON
		}
		if len(key) > maxSemanticJSONStringBytes {
			return errSemanticJSONLimit
		}
		if _, duplicate := seen[key]; duplicate {
			return errInvalidSemanticJSON
		}
		seen[key] = struct{}{}
		if depth == 0 && isSecurityFieldAlias(key) {
			return errInvalidSemanticJSON
		}
		if context == semanticContextContentPart && isContentPartFieldAlias(key) {
			return errInvalidSemanticJSON
		}
		if rulesMatchString(key, p.rules) {
			p.foundPII = true
			if p.mode != ModeDetect {
				return errSemanticPIIBlocked
			}
		}
		if members > 1 {
			if err := p.writeString(","); err != nil {
				return err
			}
		}
		if err := p.writeJSONString(key); err != nil {
			return err
		}
		if err := p.writeString(":"); err != nil {
			return err
		}
		childContext := semanticContextGeneric
		switch {
		case context == semanticContextRoot && key == "messages":
			childContext = semanticContextMessages
		case context == semanticContextMessage && key == "content":
			childContext = semanticContextMessageContent
		}
		if context == semanticContextContentPart && key == "text" && p.contentTextOverride != nil {
			if err := p.processContentTextValue(depth+1, *p.contentTextOverride); err != nil {
				return err
			}
			continue
		}
		if err := p.processValue(depth+1, childContext); err != nil {
			return err
		}
	}
	closing, err := p.decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errInvalidSemanticJSON
	}
	return p.writeString("}")
}

func (p *semanticJSONProcessor) processArray(depth int, context semanticValueContext) error {
	if err := p.writeString("["); err != nil {
		return err
	}
	items := 0
	for p.decoder.More() {
		if items > 0 {
			if err := p.writeString(","); err != nil {
				return err
			}
		}
		items++
		childContext := semanticContextGeneric
		if context == semanticContextMessages {
			childContext = semanticContextMessage
		}
		if err := p.processValue(depth+1, childContext); err != nil {
			return err
		}
	}
	closing, err := p.decoder.Token()
	if err != nil || closing != json.Delim(']') {
		return errInvalidSemanticJSON
	}
	return p.writeString("]")
}

// processContentPartsArray handles only the provider-visible schema
// messages[*].content[*] where a text part is exactly {"type":"text",
// "text":"..."}. It never joins strings from tool metadata, image URLs,
// or different messages. All text parts in one content array are aggregated in
// order even when an image or another non-text part appears between them,
// because the provider receives the entire multimodal message.
func (p *semanticJSONProcessor) processContentPartsArray(depth int) error {
	if err := p.writeString("["); err != nil {
		return err
	}

	parts := make([]semanticContentPart, 0, 8)
	rawBytes := 0
	defer func() {
		for i := range parts {
			utils.MemZero(parts[i].raw)
		}
	}()

	for p.decoder.More() {
		if len(parts) >= maxSemanticContentParts {
			return errSemanticJSONLimit
		}
		var raw json.RawMessage
		if err := p.decoder.Decode(&raw); err != nil {
			utils.MemZero(raw)
			return errInvalidSemanticJSON
		}
		if len(raw) > maxSemanticContentPartBytes || len(raw) > maxSemanticContentArrayBytes-rawBytes {
			utils.MemZero(raw)
			return errSemanticJSONLimit
		}
		rawBytes += len(raw)

		isText, text, err := inspectSemanticTextContentPart(raw)
		if err != nil {
			utils.MemZero(raw)
			return err
		}
		parts = append(parts, semanticContentPart{raw: raw, isText: isText, text: text})
	}
	closing, err := p.decoder.Token()
	if err != nil || closing != json.Delim(']') {
		return errInvalidSemanticJSON
	}

	if err := p.processSemanticMessageText(parts); err != nil {
		return err
	}
	for i := range parts {
		if i > 0 {
			if err := p.writeString(","); err != nil {
				return err
			}
		}
		if err := p.processContentPartRaw(&parts[i], depth+1); err != nil {
			return err
		}
	}
	return p.writeString("]")
}

func inspectSemanticTextContentPart(raw []byte) (bool, string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return false, "", errInvalidSemanticJSON
	}
	delim, isObject := first.(json.Delim)
	if !isObject || delim != '{' {
		values := 0
		if err := inspectBoundedSemanticValue(decoder, first, 0, &values); err != nil {
			return false, "", err
		}
		if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
			return false, "", errInvalidSemanticJSON
		}
		return false, "", nil
	}

	values := 1 // the root content-part object
	members := 0
	seenType := false
	seenText := false
	partType := ""
	text := ""
	textIsString := false
	for decoder.More() {
		members++
		if members > maxSemanticJSONObjectMembers {
			return false, "", errSemanticJSONLimit
		}
		keyToken, err := decoder.Token()
		if err != nil {
			return false, "", errInvalidSemanticJSON
		}
		key, ok := keyToken.(string)
		if !ok {
			return false, "", errInvalidSemanticJSON
		}
		if len(key) > maxSemanticJSONStringBytes {
			return false, "", errSemanticJSONLimit
		}
		if isContentPartFieldAlias(key) {
			return false, "", errInvalidSemanticJSON
		}
		switch key {
		case "type":
			if seenType {
				return false, "", errInvalidSemanticJSON
			}
			seenType = true
		case "text":
			if seenText {
				return false, "", errInvalidSemanticJSON
			}
			seenText = true
		}

		valueToken, err := decoder.Token()
		if err != nil {
			return false, "", errInvalidSemanticJSON
		}
		if value, ok := valueToken.(string); ok {
			switch key {
			case "type":
				partType = value
			case "text":
				text = value
				textIsString = true
			}
		}
		if err := inspectBoundedSemanticValue(decoder, valueToken, 1, &values); err != nil {
			return false, "", err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return false, "", errInvalidSemanticJSON
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return false, "", errInvalidSemanticJSON
	}
	return partType == "text" && seenText && textIsString, text, nil
}

// inspectBoundedSemanticValue consumes a value whose first token was already
// read. It enforces the same scalar/shape budgets before the canonical sub-parser
// runs, without constructing a map or decoded tree for an attacker-controlled
// content part. Duplicate non-schema fields remain the sub-parser's concern.
func inspectBoundedSemanticValue(decoder *json.Decoder, token json.Token, depth int, values *int) error {
	if depth > maxSemanticJSONDepth {
		return errSemanticJSONLimit
	}
	(*values)++
	if *values > maxSemanticJSONValues {
		return errSemanticJSONLimit
	}

	if delim, ok := token.(json.Delim); ok {
		switch delim {
		case '{':
			members := 0
			for decoder.More() {
				members++
				if members > maxSemanticJSONObjectMembers {
					return errSemanticJSONLimit
				}
				keyToken, err := decoder.Token()
				if err != nil {
					return errInvalidSemanticJSON
				}
				key, ok := keyToken.(string)
				if !ok {
					return errInvalidSemanticJSON
				}
				if len(key) > maxSemanticJSONStringBytes {
					return errSemanticJSONLimit
				}
				valueToken, err := decoder.Token()
				if err != nil {
					return errInvalidSemanticJSON
				}
				if err := inspectBoundedSemanticValue(decoder, valueToken, depth+1, values); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return errInvalidSemanticJSON
			}
			return nil
		case '[':
			for decoder.More() {
				valueToken, err := decoder.Token()
				if err != nil {
					return errInvalidSemanticJSON
				}
				if err := inspectBoundedSemanticValue(decoder, valueToken, depth+1, values); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return errInvalidSemanticJSON
			}
			return nil
		default:
			return errInvalidSemanticJSON
		}
	}

	switch value := token.(type) {
	case string:
		if len(value) > maxSemanticJSONStringBytes {
			return errSemanticJSONLimit
		}
	case json.Number:
		if len(value.String()) > maxSemanticJSONStringBytes {
			return errSemanticJSONLimit
		}
	case bool, nil:
	default:
		return errInvalidSemanticJSON
	}
	return nil
}

func (p *semanticJSONProcessor) processSemanticMessageText(parts []semanticContentPart) error {
	joinedBytes := 0
	for i := range parts {
		if !parts[i].isText {
			continue
		}
		if len(parts[i].text) > maxSemanticJoinedTextBytes-joinedBytes {
			return errSemanticJSONLimit
		}
		joinedBytes += len(parts[i].text)
	}
	if joinedBytes == 0 {
		return nil
	}

	var joined strings.Builder
	joined.Grow(joinedBytes)
	for i := range parts {
		if parts[i].isText {
			joined.WriteString(parts[i].text)
		}
	}
	spans, matched, err := aggregateRedactionSpans(joined.String(), p.rules)
	if err != nil {
		return err
	}
	if matched {
		p.foundPII = true
		if p.mode == ModeBlock {
			return errSemanticPIIBlocked
		}
	}

	offset := 0
	transformedBytes := 0
	for i := range parts {
		if !parts[i].isText {
			continue
		}
		override := parts[i].text
		if matched && p.mode != ModeDetect {
			override, err = redactTextPart(parts[i].text, offset, spans)
			if err != nil {
				return err
			}
		}
		if len(override) > maxSemanticJoinedTextBytes-transformedBytes {
			return errSemanticJSONLimit
		}
		transformedBytes += len(override)
		parts[i].textOverride = override
		offset += len(parts[i].text)
	}
	return nil
}

func aggregateRedactionSpans(value string, rules []RedactionRule) ([]redactionSpan, bool, error) {
	candidates := make([]redactionSpan, 0, 4)
	totalMatches := 0
	matched := false
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if rule.Pattern.MatchString("") || len(rule.Replacement) > maxSemanticJSONStringBytes {
			return nil, false, errSemanticJSONLimit
		}
		matches := rule.Pattern.FindAllStringIndex(value, maxSemanticRedactionMatches+1)
		if len(matches) > maxSemanticRedactionMatches-totalMatches {
			return nil, false, errSemanticJSONLimit
		}
		totalMatches += len(matches)
		if len(matches) > 0 {
			matched = true
		}
		for _, match := range matches {
			candidates = append(candidates, redactionSpan{
				start:       match[0],
				end:         match[1],
				replacement: rule.Replacement,
				matchWidth:  match[1] - match[0],
			})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].start == candidates[j].start {
			return candidates[i].end > candidates[j].end
		}
		return candidates[i].start < candidates[j].start
	})

	// Normalize to the union of every matched interval. Dropping an overlapping
	// later rule can expose the unmatched suffix of a wider secret (for example,
	// phone_us nested inside a China ID or credit-card match). The widest source
	// match supplies the placeholder while the merged interval removes the full
	// union, so rule ordering cannot cause partial disclosure.
	spans := make([]redactionSpan, 0, len(candidates))
	for _, candidate := range candidates {
		if len(spans) == 0 || candidate.start >= spans[len(spans)-1].end {
			spans = append(spans, candidate)
			continue
		}
		current := &spans[len(spans)-1]
		current.end = max(current.end, candidate.end)
		if candidate.matchWidth > current.matchWidth {
			current.replacement = candidate.replacement
			current.matchWidth = candidate.matchWidth
		}
	}
	return spans, matched, nil
}

// redactTextPart removes the portion of every aggregate match that overlaps
// this content part. A cross-boundary match emits the replacement once in each
// touched part, keeping every provider content part non-empty without allowing
// the original secret to be reconstructed by concatenation.
func redactTextPart(text string, globalStart int, spans []redactionSpan) (string, error) {
	globalEnd := globalStart + len(text)
	outputLen := len(text)
	touched := false
	for _, span := range spans {
		start := max(globalStart, span.start)
		end := min(globalEnd, span.end)
		if start >= end {
			continue
		}
		touched = true
		outputLen += len(span.replacement) - (end - start)
		if outputLen > maxSemanticJSONStringBytes {
			return "", errSemanticJSONLimit
		}
	}
	if !touched {
		return text, nil
	}

	var result strings.Builder
	result.Grow(outputLen)
	cursor := globalStart
	for _, span := range spans {
		start := max(globalStart, span.start)
		end := min(globalEnd, span.end)
		if start >= end {
			continue
		}
		result.WriteString(text[cursor-globalStart : start-globalStart])
		result.WriteString(span.replacement)
		cursor = end
	}
	result.WriteString(text[cursor-globalStart:])
	return result.String(), nil
}

func (p *semanticJSONProcessor) processContentPartRaw(part *semanticContentPart, depth int) error {
	decoder := json.NewDecoder(bytes.NewReader(part.raw))
	decoder.UseNumber()
	sub := semanticJSONProcessor{
		decoder:   decoder,
		output:    p.output,
		outputMax: p.outputMax,
		mode:      p.mode,
		rules:     p.rules,
		values:    p.values,
		foundPII:  p.foundPII,
	}
	if part.isText {
		sub.contentTextOverride = &part.textOverride
	}
	if err := sub.processValue(depth, semanticContextContentPart); err != nil {
		p.values = sub.values
		p.foundPII = sub.foundPII
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errInvalidSemanticJSON
	}
	p.values = sub.values
	p.foundPII = sub.foundPII
	return nil
}

func (p *semanticJSONProcessor) processContentTextValue(depth int, override string) error {
	if depth > maxSemanticJSONDepth {
		return errSemanticJSONLimit
	}
	p.values++
	if p.values > maxSemanticJSONValues {
		return errSemanticJSONLimit
	}
	token, err := p.decoder.Token()
	if err != nil {
		return errInvalidSemanticJSON
	}
	value, ok := token.(string)
	if !ok {
		return errInvalidSemanticJSON
	}
	if len(value) > maxSemanticJSONStringBytes || len(override) > maxSemanticJSONStringBytes {
		return errSemanticJSONLimit
	}
	return p.writeJSONString(override)
}

func (p *semanticJSONProcessor) processStringValue(value string) error {
	spans, matched, err := aggregateRedactionSpans(value, p.rules)
	if err != nil {
		return err
	}
	if matched {
		p.foundPII = true
		if p.mode == ModeBlock {
			return errSemanticPIIBlocked
		}
	}
	if p.output == nil {
		return nil
	}
	redacted := value
	if matched {
		redacted, err = redactTextPart(value, 0, spans)
		if err != nil {
			return err
		}
	}
	return p.writeJSONString(redacted)
}

func (p *semanticJSONProcessor) writeJSONString(value string) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return errInvalidSemanticJSON
	}
	err = p.writeBytes(encoded)
	utils.MemZero(encoded)
	return err
}

func (p *semanticJSONProcessor) writeString(value string) error {
	return p.writeBytes([]byte(value))
}

func (p *semanticJSONProcessor) writeBytes(value []byte) error {
	if p.output == nil {
		return nil
	}
	if int64(len(value)) > p.outputMax-int64(p.output.len()) {
		return errSemanticJSONLimit
	}
	return p.output.append(value)
}

func (p *semanticJSONProcessor) zeroOutput() {
	if p.output != nil {
		p.output.zero()
	}
}

func isSecurityFieldAlias(key string) bool {
	return strings.EqualFold(key, "model") && key != "model" ||
		strings.EqualFold(key, "stream") && key != "stream"
}

func isContentPartFieldAlias(key string) bool {
	return strings.EqualFold(key, "type") && key != "type" ||
		strings.EqualFold(key, "text") && key != "text"
}

func rulesMatchString(value string, rules []RedactionRule) bool {
	for _, rule := range rules {
		if rule.Enabled && rule.Pattern.MatchString(value) {
			return true
		}
	}
	return false
}

// --- PII Scanner ---

type piiScanner struct {
	mu    sync.RWMutex
	mode  RedactionMode
	rules []RedactionRule
}

func newPIIScanner(cfg RedactionConfig) *piiScanner {
	rules := cfg.Rules
	if len(rules) == 0 {
		rules = DefaultRedactionRules()
	}
	mode := cfg.Mode
	if mode == "" {
		mode = ModeRedact
	}
	return &piiScanner{
		mode:  mode,
		rules: rules,
	}
}

// Scan checks text for PII patterns and returns the first finding.
// Callers only need presence, so bounding the result prevents match-count
// amplification on large, repetitive request bodies.
func (s *piiScanner) Scan(text []byte) []PIIFinding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, rule := range s.rules {
		if !rule.Enabled {
			continue
		}
		if match := rule.Pattern.FindIndex(text); match != nil {
			return []PIIFinding{{
				Rule:  rule.Name,
				Start: match[0],
				End:   match[1],
			}}
		}
	}
	return nil
}

// Redact replaces all PII matches with their configured replacements.
func (s *piiScanner) Redact(text []byte) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return redactBytes(text, s.rules)
}

func redactBytes(text []byte, rules []RedactionRule) []byte {
	result := text
	for _, rule := range rules {
		if !rule.Enabled || !rule.Pattern.Match(result) {
			continue
		}
		replaced := rule.Pattern.ReplaceAll(result, []byte(rule.Replacement))
		if !sameBuffer(result, text) {
			utils.MemZero(result)
		}
		result = replaced
	}
	return result
}

// PIIFinding represents a detected PII occurrence.
type PIIFinding struct {
	Rule  string // Which rule matched
	Start int    // Start position in text
	End   int    // End position in text
}

// blockErrorJSON creates a PII block error response.
func blockErrorJSON() []byte {
	return []byte(`{"error":{"message":"request blocked: contains personally identifiable information","type":"content_policy_error"}}`)
}
