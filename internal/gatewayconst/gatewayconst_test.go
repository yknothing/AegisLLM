package gatewayconst

import "testing"

func TestIsSupportedProviderType(t *testing.T) {
	for _, providerType := range []string{
		ProviderTypeOpenAI,
		ProviderTypeDeepSeek,
		ProviderTypeAnthropic,
		ProviderTypeGoogle,
		ProviderTypeAzure,
		ProviderTypeOpenRouter,
	} {
		if !IsSupportedProviderType(providerType) {
			t.Fatalf("IsSupportedProviderType(%q) = false", providerType)
		}
	}
	if IsSupportedProviderType("bedrock") {
		t.Fatal("IsSupportedProviderType accepted bedrock")
	}
}

func TestIsLoopbackHost(t *testing.T) {
	if !IsLoopbackHost("127.0.0.1") || !IsLoopbackHost("localhost") || !IsLoopbackHost("::1") {
		t.Fatal("IsLoopbackHost rejected a loopback host")
	}
	if IsLoopbackHost("0.0.0.0") {
		t.Fatal("IsLoopbackHost accepted 0.0.0.0")
	}
}
