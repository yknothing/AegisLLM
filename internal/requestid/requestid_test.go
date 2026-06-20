package requestid

import (
	"strings"
	"testing"
)

func TestSafeAcceptsCommonRequestIDFormats(t *testing.T) {
	for _, id := range []string{
		"req_0123456789abcdef",
		"550e8400-e29b-41d4-a716-446655440000",
		"01HZY7G9P4X3Y8N9D2V6Q1W0AB",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
		"service.request.id:span",
		strings.Repeat("a", MaxLength),
	} {
		if !Safe(id) {
			t.Fatalf("Safe(%q) = false, want true", id)
		}
	}
}

func TestSafeRejectsUnsafeRequestIDFormats(t *testing.T) {
	for _, id := range []string{
		"",
		" client-req",
		"client-req ",
		"client\nreq",
		"client\rreq",
		"client\treq",
		"client/req",
		"client=req",
		"client-请求",
		strings.Repeat("a", MaxLength+1),
	} {
		if Safe(id) {
			t.Fatalf("Safe(%q) = true, want false", id)
		}
	}
}

func TestGenerateReturnsSafeGatewayRequestID(t *testing.T) {
	id := Generate()

	if !strings.HasPrefix(id, "req_") {
		t.Fatalf("Generate() = %q, want req_ prefix", id)
	}
	if !Safe(id) {
		t.Fatalf("Generate() = %q, want safe request ID", id)
	}
}
