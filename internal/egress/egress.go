// Package egress centralizes outbound host allowlist matching.
//
// SECURITY: Exact host entries match only that normalized host. Subdomain
// matching requires an explicit "*." prefix in the configured allowlist entry.
package egress

import (
	"net"
	"net/url"
	"strings"
)

// HostAllowed reports whether host is allowed by the configured egress
// allowlist. Entries are normalized before comparison.
func HostAllowed(host string, allowedDomains []string) bool {
	host = NormalizeHost(host)
	if host == "" {
		return false
	}

	for _, rawAllowed := range allowedDomains {
		allowed := normalizeAllowed(rawAllowed)
		if allowed.host == "" {
			continue
		}
		if allowed.wildcard {
			if host != allowed.host && strings.HasSuffix(host, "."+allowed.host) {
				return true
			}
			continue
		}
		if host == allowed.host {
			return true
		}
	}

	return false
}

type allowedHost struct {
	host     string
	wildcard bool
}

func normalizeAllowed(raw string) allowedHost {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return allowedHost{}
	}

	wildcard := false
	if strings.HasPrefix(raw, "*.") {
		wildcard = true
		raw = strings.TrimPrefix(raw, "*.")
	} else if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err == nil {
			raw = parsed.Hostname()
		}
	}

	return allowedHost{
		host:     NormalizeHost(raw),
		wildcard: wildcard,
	}
}

// NormalizeHost canonicalizes a hostname for egress comparison.
func NormalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	return host
}
