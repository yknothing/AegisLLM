package utils

import "testing"

func TestValidateProviderCredentialHeaderValueContract(t *testing.T) {
	tests := []struct {
		name       string
		credential []byte
		wantErr    bool
	}{
		{name: "valid common key", credential: []byte("sk-proj_AbC123-._~+/=")},
		{name: "valid printable ASCII including space", credential: []byte("key with space")},
		{name: "empty", credential: nil, wantErr: true},
		{name: "oversized", credential: make([]byte, MaxProviderCredentialBytes+1), wantErr: true},
		{name: "embedded newline", credential: []byte("sk-first\nsk-second"), wantErr: true},
		{name: "embedded carriage return", credential: []byte("sk-first\rsk-second"), wantErr: true},
		{name: "NUL", credential: []byte{'s', 'k', 0, 'x'}, wantErr: true},
		{name: "horizontal tab control", credential: []byte("sk\tkey"), wantErr: true},
		{name: "unit separator control", credential: []byte{'s', 'k', 0x1f, 'x'}, wantErr: true},
		{name: "DEL", credential: []byte{'s', 'k', 0x7f, 'x'}, wantErr: true},
		{name: "non ASCII", credential: []byte("sk-密钥"), wantErr: true},
		{name: "unsupported byte", credential: []byte{'s', 'k', 0xff}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProviderCredentialHeaderValue(tt.credential)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateProviderCredentialHeaderValue error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}
