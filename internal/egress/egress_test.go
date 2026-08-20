package egress

import (
	"net/netip"
	"strings"
	"testing"
)

func TestHostAllowedRequiresExactHostByDefault(t *testing.T) {
	allowed := []string{"api.openai.com"}

	if !HostAllowed("api.openai.com", allowed) {
		t.Fatal("HostAllowed rejected exact allowed host")
	}
	if HostAllowed("tenant.api.openai.com", allowed) {
		t.Fatal("HostAllowed accepted implicit subdomain without wildcard")
	}
}

func TestHostAllowedSupportsExplicitWildcardSubdomains(t *testing.T) {
	allowed := []string{"*.openai.com"}

	if !HostAllowed("api.openai.com", allowed) {
		t.Fatal("HostAllowed rejected explicit wildcard subdomain")
	}
	if !HostAllowed("tenant.api.openai.com", allowed) {
		t.Fatal("HostAllowed rejected nested explicit wildcard subdomain")
	}
	if HostAllowed("openai.com", allowed) {
		t.Fatal("HostAllowed accepted wildcard apex host")
	}
}

func TestHostAllowedRejectsURLFormAllowlistEntries(t *testing.T) {
	allowed := []string{"https://API.OpenAI.com:443/path"}

	if HostAllowed("api.openai.com:443", allowed) {
		t.Fatal("HostAllowed accepted URL-form allowlist entry")
	}
}

func TestHostAllowedRequiresExactNonDefaultPort(t *testing.T) {
	if HostAllowed("api.openai.com:8443", []string{"api.openai.com"}) {
		t.Fatal("HostAllowed let a host-only rule authorize a non-default port")
	}
	if !HostAllowed("api.openai.com:8443", []string{"api.openai.com:8443"}) {
		t.Fatal("HostAllowed rejected an exact host and non-default port")
	}
	if HostAllowed("tenant.openai.com:8443", []string{"*.openai.com"}) {
		t.Fatal("HostAllowed let a wildcard host authorize a non-default port")
	}
}

func TestHostAllowedRequiresExplicitIPLiteralPort(t *testing.T) {
	if HostAllowed("127.0.0.1:443", []string{"127.0.0.1"}) {
		t.Fatal("HostAllowed accepted an IP literal rule without an explicit port")
	}
	if !HostAllowed("127.0.0.1:443", []string{"127.0.0.1:443"}) {
		t.Fatal("HostAllowed rejected an exact IP literal and port")
	}
}

func TestParseAuthorityAcceptsBracketedIPv6WithExactPort(t *testing.T) {
	const address = "2606:4700:4700::1111"
	endpoint, err := ParseAuthority("[" + address + "]:8443")
	if err != nil {
		t.Fatalf("ParseAuthority rejected bracketed IPv6 authority: %v", err)
	}
	if !endpoint.IPLiteral {
		t.Fatal("ParseAuthority did not classify IPv6 authority as an IP literal")
	}
	if endpoint.IP != netip.MustParseAddr(address) {
		t.Fatalf("endpoint IP = %s, want %s", endpoint.IP, address)
	}
	if endpoint.Host != address {
		t.Fatalf("endpoint host = %q, want normalized IPv6 %q", endpoint.Host, address)
	}
	if endpoint.Port != "8443" {
		t.Fatalf("endpoint port = %q, want 8443", endpoint.Port)
	}
}

func TestHostAllowedRequiresExactIPv6AddressAndPort(t *testing.T) {
	allowed := []string{"[2606:4700:4700::1111]:8443"}
	if !HostAllowed("[2606:4700:4700::1111]:8443", allowed) {
		t.Fatal("HostAllowed rejected exact bracketed IPv6 authority")
	}
	if HostAllowed("[2606:4700:4700::1111]:443", allowed) {
		t.Fatal("HostAllowed accepted IPv6 authority on a different port")
	}
	if HostAllowed("[2606:4700:4700::1001]:8443", allowed) {
		t.Fatal("HostAllowed accepted a different IPv6 address")
	}
}

func TestParseAuthorityRejectsAmbiguousOrMalformedIPv6Authorities(t *testing.T) {
	tests := []string{
		"2606:4700:4700::1111",
		"2606:4700:4700::1111:443",
		"[2606:4700:4700::1111]",
		"[2606:4700:4700::1111]:",
		"[2606:4700:4700::1111]:0",
		"[2606:4700:4700::1111]:65536",
		"[fe80::1%en0]:443",
		"[2606:4700:4700::1111]:443:extra",
	}
	for _, authority := range tests {
		t.Run(authority, func(t *testing.T) {
			if _, err := ParseAuthority(authority); err == nil {
				t.Fatalf("ParseAuthority accepted malformed IPv6 authority %q", authority)
			}
		})
	}
}

func TestValidateAllowlistRejectsMalformedEntries(t *testing.T) {
	tests := []string{
		"",
		" api.openai.com",
		"user@api.openai.com",
		"api.openai.com/path",
		"*.openai.com:8443",
		"127.0.0.1",
		"[::1]",
		"bad host",
	}
	for _, entry := range tests {
		t.Run(entry, func(t *testing.T) {
			if err := ValidateAllowlist([]string{entry}); err == nil {
				t.Fatalf("ValidateAllowlist accepted %q", entry)
			}
		})
	}
}

func TestValidateAllowlistDoesNotEchoRejectedEntry(t *testing.T) {
	const canary = "CANARY-egress-userinfo-secret-94d7c2"
	err := ValidateAllowlist([]string{"api.openai.com", "https://user:" + canary + "@api.openai.com"})
	if err == nil {
		t.Fatal("ValidateAllowlist accepted URL-form userinfo")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("allowlist validation error leaked rejected entry secret: %v", err)
	}
}

func TestParseHTTPSURLDoesNotEchoMalformedTarget(t *testing.T) {
	const canary = "CANARY-malformed-target-secret-71c9e4"
	_, err := ParseHTTPSURL("https://user:" + canary + "@api.openai.com/%zz")
	if err == nil {
		t.Fatal("ParseHTTPSURL accepted malformed escape")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("target URL parse error leaked malformed URL secret: %v", err)
	}
}

func TestPublicDNSAddressRejectsIANAReservedRanges(t *testing.T) {
	tests := []string{
		"192.88.99.1",     // deprecated 6to4 relay anycast
		"192.31.196.1",    // AS112-v4 special-purpose service
		"192.52.193.1",    // AMT special-purpose service
		"192.175.48.1",    // AS112 direct-delegation service
		"100:0:0:1::1",    // dummy IPv6 prefix
		"2001:100::1",     // unallocated IETF protocol assignment space
		"2620:4f:8000::1", // AS112-v6 special-purpose service
		"3000::1",         // reserved inside the broad 2000::/3 range
		"3ffe::1",         // returned 6bone space
		"4000::1",         // IETF-reserved IPv6 space outside 2000::/3
		"6000::1",         // IETF-reserved IPv6 space outside 2000::/3
	}
	for _, address := range tests {
		t.Run(address, func(t *testing.T) {
			if PublicDNSAddress(netip.MustParseAddr(address)) {
				t.Fatalf("PublicDNSAddress accepted IANA special-purpose address %s", address)
			}
		})
	}
}

func TestPublicDNSAddressAllowsOrdinaryPublicAddresses(t *testing.T) {
	for _, address := range []string{"93.184.216.34", "2606:4700:4700::1111"} {
		t.Run(address, func(t *testing.T) {
			if !PublicDNSAddress(netip.MustParseAddr(address)) {
				t.Fatalf("PublicDNSAddress rejected ordinary public address %s", address)
			}
		})
	}
}

func TestHostAllowedRejectsSubstringBypass(t *testing.T) {
	allowed := []string{"api.openai.com"}

	if HostAllowed("api.openai.com.evil.example", allowed) {
		t.Fatal("HostAllowed accepted substring bypass")
	}
}
