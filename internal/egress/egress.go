// Package egress centralizes outbound endpoint allowlist validation and matching.
//
// SECURITY: Rules are strict host or exact host:port authorities. Host-only and
// wildcard rules authorize HTTPS port 443 only. IP literals require an explicit
// port so they cannot be confused with DNS-host rules.
package egress

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const defaultHTTPSPort = "443"

// ianaAllocatedGlobalIPv6Prefixes mirrors ALLOCATED entries intended for
// ordinary global unicast in the IANA IPv6 Global Unicast Address Space
// registry (last reviewed 2025-10-10). The special 2001::/23 and 2002::/16
// allocations are deliberately excluded and denied below.
var ianaAllocatedGlobalIPv6Prefixes = []netip.Prefix{
	netip.MustParsePrefix("2001:200::/23"),
	netip.MustParsePrefix("2001:400::/23"),
	netip.MustParsePrefix("2001:600::/23"),
	netip.MustParsePrefix("2001:800::/22"),
	netip.MustParsePrefix("2001:c00::/23"),
	netip.MustParsePrefix("2001:e00::/23"),
	netip.MustParsePrefix("2001:1200::/23"),
	netip.MustParsePrefix("2001:1400::/22"),
	netip.MustParsePrefix("2001:1800::/23"),
	netip.MustParsePrefix("2001:1a00::/23"),
	netip.MustParsePrefix("2001:1c00::/22"),
	netip.MustParsePrefix("2001:2000::/19"),
	netip.MustParsePrefix("2001:4000::/23"),
	netip.MustParsePrefix("2001:4200::/23"),
	netip.MustParsePrefix("2001:4400::/23"),
	netip.MustParsePrefix("2001:4600::/23"),
	netip.MustParsePrefix("2001:4800::/23"),
	netip.MustParsePrefix("2001:4a00::/23"),
	netip.MustParsePrefix("2001:4c00::/23"),
	netip.MustParsePrefix("2001:5000::/20"),
	netip.MustParsePrefix("2001:8000::/19"),
	netip.MustParsePrefix("2001:a000::/20"),
	netip.MustParsePrefix("2001:b000::/20"),
	netip.MustParsePrefix("2003::/18"),
	netip.MustParsePrefix("2400::/12"),
	netip.MustParsePrefix("2410::/12"),
	netip.MustParsePrefix("2600::/12"),
	netip.MustParsePrefix("2610::/23"),
	netip.MustParsePrefix("2620::/23"),
	netip.MustParsePrefix("2630::/12"),
	netip.MustParsePrefix("2800::/12"),
	netip.MustParsePrefix("2a00::/12"),
	netip.MustParsePrefix("2a10::/12"),
	netip.MustParsePrefix("2c00::/12"),
}

// deniedDNSPrefixes mirrors the IANA IPv4 and IPv6 Special-Purpose Address
// registries (last reviewed 2025-10-09). A DNS answer for a protocol/service
// allocation is not an ordinary provider endpoint even when IANA marks that
// allocation globally reachable, so this boundary rejects every such prefix.
var deniedDNSPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	// IANA marks 2001::/23 as protocol-assignment space rather than a
	// generally routed provider range. Deny the whole parent conservatively,
	// including its more-specific protocol anycast allocations.
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

// Rule is one validated outbound allowlist entry.
type Rule struct {
	host      string
	port      string
	wildcard  bool
	ipLiteral bool
	ip        netip.Addr
}

// Endpoint is one normalized host and effective port.
type Endpoint struct {
	Host      string
	Port      string
	IPLiteral bool
	IP        netip.Addr
}

// ValidateAllowlist reports whether every configured entry has strict syntax.
func ValidateAllowlist(entries []string) error {
	_, err := ParseAllowlist(entries)
	return err
}

// ParseAllowlist validates and compiles configured outbound endpoint rules.
func ParseAllowlist(entries []string) ([]Rule, error) {
	if len(entries) == 0 {
		return nil, errors.New("egress allowlist must not be empty")
	}
	rules := make([]Rule, 0, len(entries))
	for index, raw := range entries {
		rule, err := parseRule(raw)
		if err != nil {
			// Configuration errors reach startup logs. Never echo the rejected
			// value because malformed URL-form entries may contain userinfo.
			return nil, fmt.Errorf("egress allowlist entry %d: %w", index, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// HostAllowed reports whether an authority is authorized by strict allowlist
// rules. A missing target port has the effective HTTPS port 443.
func HostAllowed(authority string, allowedDomains []string) bool {
	rules, err := ParseAllowlist(allowedDomains)
	if err != nil {
		return false
	}
	endpoint, err := parseAuthority(authority, true)
	if err != nil {
		return false
	}
	return EndpointAllowed(endpoint, rules)
}

// ParseAuthority validates a target host:port authority. An explicit numeric
// port is required because this function is used at the network dial boundary.
func ParseAuthority(raw string) (Endpoint, error) {
	return parseAuthority(raw, false)
}

// ParseHTTPSURL validates an absolute HTTPS target and returns its normalized
// host plus effective port. Credentials and fragments are never valid egress
// target metadata.
func ParseHTTPSURL(raw string) (Endpoint, error) {
	if strings.Contains(raw, "#") {
		return Endpoint{}, errors.New("target URL must not contain a fragment")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		// net/url parse errors embed the complete raw URL. Provider URLs are
		// privileged configuration and malformed userinfo may contain secrets,
		// so startup errors must not wrap or echo the parser error.
		return Endpoint{}, errors.New("invalid target URL")
	}
	if parsed.Scheme != "https" || parsed.Opaque != "" {
		return Endpoint{}, errors.New("target URL must use hierarchical https")
	}
	if parsed.User != nil {
		return Endpoint{}, errors.New("target URL must not contain userinfo")
	}
	if parsed.Fragment != "" || parsed.RawFragment != "" {
		return Endpoint{}, errors.New("target URL must not contain a fragment")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return Endpoint{}, errors.New("target URL must include a host")
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return Endpoint{}, errors.New("target URL must not contain an empty port")
	}
	port := defaultHTTPSPort
	if parsed.Port() != "" {
		port, err = normalizePort(parsed.Port())
		if err != nil {
			return Endpoint{}, fmt.Errorf("invalid target URL port: %w", err)
		}
	}
	endpoint, err := endpointForHost(parsed.Hostname(), port)
	if err != nil {
		return Endpoint{}, fmt.Errorf("invalid target URL host: %w", err)
	}
	return endpoint, nil
}

// EndpointAllowed reports whether a normalized endpoint matches a compiled rule.
func EndpointAllowed(endpoint Endpoint, rules []Rule) bool {
	for _, rule := range rules {
		if endpoint.Port != rule.port {
			continue
		}
		if endpoint.IPLiteral {
			if rule.ipLiteral && endpoint.IP == rule.ip {
				return true
			}
			continue
		}
		if rule.ipLiteral {
			continue
		}
		if rule.wildcard {
			if endpoint.Host != rule.host && strings.HasSuffix(endpoint.Host, "."+rule.host) {
				return true
			}
			continue
		}
		if endpoint.Host == rule.host {
			return true
		}
	}
	return false
}

// PublicDNSAddress reports whether a DNS result is safe for provider egress.
// Explicit IP-literal rules are handled separately and do not call this helper.
func PublicDNSAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() ||
		address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	// netip treats future-reserved IPv6 unicast space as global unicast. Only
	// current IANA ALLOCATED ranges are eligible for DNS-derived egress.
	if address.Is6() && !prefixesContain(ianaAllocatedGlobalIPv6Prefixes, address) {
		return false
	}
	for _, prefix := range deniedDNSPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func prefixesContain(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func parseRule(raw string) (Rule, error) {
	if raw == "" {
		return Rule{}, errors.New("entry must not be empty")
	}
	if raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, " \t\r\n/@?#") || strings.Contains(raw, "://") {
		return Rule{}, errors.New("entry must be a host, wildcard host, or exact host:port")
	}

	wildcard := strings.HasPrefix(raw, "*.")
	if wildcard {
		raw = strings.TrimPrefix(raw, "*.")
		if strings.Contains(raw, ":") {
			return Rule{}, errors.New("wildcard entries cannot specify a port")
		}
	}

	endpoint, explicitPort, err := parseRuleAuthority(raw)
	if err != nil {
		return Rule{}, err
	}
	if wildcard && endpoint.IPLiteral {
		return Rule{}, errors.New("wildcard entries require a DNS hostname")
	}
	if endpoint.IPLiteral && !explicitPort {
		return Rule{}, errors.New("IP literal entries require an explicit port")
	}

	return Rule{
		host:      endpoint.Host,
		port:      endpoint.Port,
		wildcard:  wildcard,
		ipLiteral: endpoint.IPLiteral,
		ip:        endpoint.IP,
	}, nil
}

func parseRuleAuthority(raw string) (Endpoint, bool, error) {
	explicitPort := false
	authority := raw
	switch {
	case strings.HasPrefix(raw, "[") || strings.Count(raw, ":") == 1:
		host, port, err := net.SplitHostPort(raw)
		if err != nil {
			return Endpoint{}, false, errors.New("invalid host:port authority")
		}
		authority = host
		normalizedPort, err := normalizePort(port)
		if err != nil {
			return Endpoint{}, false, err
		}
		explicitPort = true
		endpoint, err := endpointForHost(authority, normalizedPort)
		return endpoint, explicitPort, err
	case strings.Count(raw, ":") > 1:
		// A bare IPv6 address has no unambiguous port and is rejected below.
		authority = raw
	}

	endpoint, err := endpointForHost(authority, defaultHTTPSPort)
	return endpoint, explicitPort, err
}

func parseAuthority(raw string, allowImplicitPort bool) (Endpoint, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, " \t\r\n/@?#") || strings.Contains(raw, "://") {
		return Endpoint{}, errors.New("invalid target authority")
	}
	endpoint, explicitPort, err := parseRuleAuthority(raw)
	if err != nil {
		return Endpoint{}, err
	}
	if !explicitPort && !allowImplicitPort {
		return Endpoint{}, errors.New("target authority requires an explicit port")
	}
	return endpoint, nil
}

func endpointForHost(rawHost, port string) (Endpoint, error) {
	host := strings.TrimSuffix(rawHost, ".")
	if host == "" {
		return Endpoint{}, errors.New("host must not be empty")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return Endpoint{}, errors.New("scoped IP literals are not allowed")
		}
		addr = addr.Unmap()
		return Endpoint{Host: addr.String(), Port: port, IPLiteral: true, IP: addr}, nil
	}
	if strings.Contains(host, ":") {
		return Endpoint{}, errors.New("invalid IP literal")
	}
	host = strings.ToLower(host)
	if err := validateDNSName(host); err != nil {
		return Endpoint{}, err
	}
	return Endpoint{Host: host, Port: port}, nil
}

func validateDNSName(host string) error {
	if len(host) > 253 {
		return errors.New("DNS hostname exceeds 253 bytes")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return errors.New("DNS hostname contains an invalid label length")
		}
		for index, char := range label {
			isAlphaNumeric := char >= 'a' && char <= 'z' || char >= '0' && char <= '9'
			if !isAlphaNumeric && char != '-' {
				return errors.New("DNS hostname contains an invalid character")
			}
			if char == '-' && (index == 0 || index == len(label)-1) {
				return errors.New("DNS hostname label cannot start or end with a hyphen")
			}
		}
	}
	return nil
}

func normalizePort(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("port must not be empty")
	}
	for _, char := range raw {
		if char < '0' || char > '9' {
			return "", errors.New("port must be numeric")
		}
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("port must be between 1 and 65535")
	}
	return strconv.Itoa(port), nil
}

// NormalizeHost canonicalizes a hostname for compatibility with callers that
// do not yet carry an endpoint port. Invalid values normalize to an empty host.
func NormalizeHost(host string) string {
	endpoint, err := parseAuthority(host, true)
	if err != nil {
		return ""
	}
	return endpoint.Host
}
