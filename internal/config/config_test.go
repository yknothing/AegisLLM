package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadRejectsUnknownFieldsAtEveryConfigBoundary(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "root",
			data: bytes.Replace(example, []byte(`"server": {`), []byte(`"unexpected_root": true, "server": {`), 1),
		},
		{
			name: "server",
			data: bytes.Replace(example, []byte(`"address": ":8080",`), []byte(`"adress": ":9090", "address": ":8080",`), 1),
		},
		{
			name: "tls",
			data: bytes.Replace(example, []byte(`"enabled": false,`), []byte(`"enabeld": true, "enabled": false,`), 1),
		},
		{
			name: "auth",
			data: bytes.Replace(example, []byte(`"issuer": "aegis"`), []byte(`"isuer": "aegis", "issuer": "aegis"`), 1),
		},
		{
			name: "provider",
			data: bytes.Replace(example, []byte(`"name": "OpenAI Primary",`), []byte(`"naem": "OpenAI Primary", "name": "OpenAI Primary",`), 1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "aegis.json")
			if err := os.WriteFile(path, tt.data, 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("Load error = %v, want unknown field rejection", err)
			}
		})
	}
}

func TestLoadRejectsAmbiguousOrNonCanonicalJSONMembers(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}

	const canary = "CANARY_CONFIG_MEMBER_VALUE_7e43"
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{
			name: "root duplicate",
			old:  `"auth": {`,
			new:  `"auth": {"issuer": "` + canary + `"}, "auth": {`,
		},
		{
			name: "root ASCII case-fold collision",
			old:  `"auth": {`,
			new:  `"AUTH": {"issuer": "` + canary + `"}, "auth": {`,
		},
		{
			name: "root sole case mismatch",
			old:  `"auth": {`,
			new:  `"AUTH": {`,
		},
		{
			name: "auth duplicate",
			old:  `"issuer": "aegis",`,
			new:  `"issuer": "` + canary + `", "issuer": "aegis",`,
		},
		{
			name: "auth ASCII case-fold collision",
			old:  `"issuer": "aegis",`,
			new:  `"ISSUER": "` + canary + `", "issuer": "aegis",`,
		},
		{
			name: "auth sole case mismatch",
			old:  `"issuer": "aegis",`,
			new:  `"ISSUER": "aegis",`,
		},
		{
			name: "provider duplicate",
			old:  `"id": "openai-primary",`,
			new:  `"id": "` + canary + `", "id": "openai-primary",`,
		},
		{
			name: "provider ASCII case-fold collision",
			old:  `"id": "openai-primary",`,
			new:  `"ID": "` + canary + `", "id": "openai-primary",`,
		},
		{
			name: "provider sole case mismatch",
			old:  `"id": "openai-primary",`,
			new:  `"ID": "openai-primary",`,
		},
		{
			name: "egress duplicate",
			old:  `"allowed_domains": [`,
			new:  `"allowed_domains": ["` + canary + `"], "allowed_domains": [`,
		},
		{
			name: "egress ASCII case-fold collision",
			old:  `"allowed_domains": [`,
			new:  `"ALLOWED_DOMAINS": ["` + canary + `"], "allowed_domains": [`,
		},
		{
			name: "egress sole case mismatch",
			old:  `"allowed_domains": [`,
			new:  `"ALLOWED_DOMAINS": [`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := bytes.Replace(example, []byte(tt.old), []byte(tt.new), 1)
			if bytes.Equal(data, example) {
				t.Fatal("fixture mutation did not match canonical config")
			}

			_, err := Load(writeConfig(t, string(data)))
			if err == nil {
				t.Fatal("Load accepted ambiguous or non-canonical JSON member")
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatalf("Load error leaked config value: %v", err)
			}
		})
	}
}

func TestLoadAcceptsCanonicalJSONMembers(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	cfg, err := Load(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("Load canonical example config: %v", err)
	}
	if cfg.Auth.Issuer != "aegis" || len(cfg.Providers) != 2 || len(cfg.Egress.AllowedDomains) != 2 {
		t.Fatalf("Load canonical example config returned unexpected fields")
	}
}

func TestLoadRejectsExplicitNullForNonNullableConfigValues(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}

	tests := []struct {
		name string
		path []any
	}{
		{name: "root server", path: []any{"server"}},
		{name: "root kms", path: []any{"kms"}},
		{name: "root providers", path: []any{"providers"}},
		{name: "root auth", path: []any{"auth"}},
		{name: "root rate limit", path: []any{"rate_limit"}},
		{name: "root quota", path: []any{"quota"}},
		{name: "root store", path: []any{"store"}},
		{name: "root egress", path: []any{"egress"}},

		{name: "server address", path: []any{"server", "address"}},
		{name: "server read timeout", path: []any{"server", "read_timeout"}},
		{name: "server write timeout", path: []any{"server", "write_timeout"}},
		{name: "server shutdown timeout", path: []any{"server", "shutdown_timeout"}},
		{name: "server max request body size", path: []any{"server", "max_request_body_size"}},
		{name: "server tls", path: []any{"server", "tls"}},
		{name: "server tls enabled", path: []any{"server", "tls", "enabled"}},
		{name: "server tls cert file", path: []any{"server", "tls", "cert_file"}},
		{name: "server tls key file", path: []any{"server", "tls", "key_file"}},
		{name: "server tls ca file", path: []any{"server", "tls", "ca_file"}},
		{name: "server tls min version", path: []any{"server", "tls", "min_version"}},

		{name: "kms mode", path: []any{"kms", "mode"}},
		{name: "kms local", path: []any{"kms", "local"}},
		{name: "kms local master key env", path: []any{"kms", "local", "master_key_env"}},
		{name: "kms local key store path", path: []any{"kms", "local", "key_store_path"}},
		{name: "kms local minimum envelope version", path: []any{"kms", "local", "minimum_envelope_version"}},
		{name: "kms vault", path: []any{"kms", "vault"}},
		{name: "kms vault address", path: []any{"kms", "vault", "address"}},
		{name: "kms vault path", path: []any{"kms", "vault", "path"}},
		{name: "kms vault token env", path: []any{"kms", "vault", "token_env"}},

		{name: "provider element", path: []any{"providers", 0}},
		{name: "provider id", path: []any{"providers", 0, "id"}},
		{name: "provider name", path: []any{"providers", 0, "name"}},
		{name: "provider type", path: []any{"providers", 0, "type"}},
		{name: "provider base url", path: []any{"providers", 0, "base_url"}},
		{name: "provider api key id", path: []any{"providers", 0, "api_key_id"}},
		{name: "provider models", path: []any{"providers", 0, "models"}},
		{name: "provider model element", path: []any{"providers", 0, "models", 0}},
		{name: "provider weight", path: []any{"providers", 0, "weight"}},
		{name: "provider max rpm", path: []any{"providers", 0, "max_rpm"}},
		{name: "provider max tpm", path: []any{"providers", 0, "max_tpm"}},
		{name: "provider enabled", path: []any{"providers", 0, "enabled"}},
		{name: "provider priority", path: []any{"providers", 0, "priority"}},

		{name: "auth jwt signing key env", path: []any{"auth", "jwt_signing_key_env"}},
		{name: "auth token expiry", path: []any{"auth", "token_expiry"}},
		{name: "auth issuer", path: []any{"auth", "issuer"}},
		{name: "auth revocation", path: []any{"auth", "revocation"}},
		{name: "auth revocation backend", path: []any{"auth", "revocation", "backend"}},
		{name: "auth revocation file path", path: []any{"auth", "revocation", "file_path"}},
		{name: "auth revocation refresh interval", path: []any{"auth", "revocation", "refresh_interval"}},

		{name: "rate limit enabled", path: []any{"rate_limit", "enabled"}},
		{name: "rate limit backend", path: []any{"rate_limit", "backend"}},
		{name: "rate limit redis url", path: []any{"rate_limit", "redis_url"}},
		{name: "rate limit default rpm", path: []any{"rate_limit", "default_rpm"}},
		{name: "rate limit default tpm", path: []any{"rate_limit", "default_tpm"}},
		{name: "rate limit default max concurrency", path: []any{"rate_limit", "default_max_concurrency"}},

		{name: "quota enabled", path: []any{"quota", "enabled"}},
		{name: "quota backend", path: []any{"quota", "backend"}},
		{name: "quota dsn", path: []any{"quota", "dsn"}},
		{name: "quota default budget", path: []any{"quota", "default_budget"}},

		{name: "root admin", path: []any{"admin"}},
		{name: "admin enabled", path: []any{"admin", "enabled"}},

		{name: "store type", path: []any{"store", "type"}},
		{name: "store dsn", path: []any{"store", "dsn"}},

		{name: "egress allowed domains", path: []any{"egress", "allowed_domains"}},
		{name: "egress allowed domain element", path: []any{"egress", "allowed_domains", 0}},
	}

	const wantErr = "parsing config file: json: null is not allowed in configuration"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := configWithNullAtPath(t, example, tt.path)
			_, err := Load(writeConfig(t, string(data)))
			if err == nil {
				t.Fatal("Load accepted explicit null for a non-nullable configuration value")
			}
			if err.Error() != wantErr {
				t.Fatalf("Load error = %q, want generic null rejection %q", err, wantErr)
			}
			for _, canary := range []string{nullCanaryServerValue, nullCanaryProviderValue} {
				if strings.Contains(err.Error(), canary) {
					t.Fatalf("Load error leaked config canary: %v", err)
				}
			}
		})
	}
}

func TestLoadPreservesDefaultsForCanonicalOmittedFields(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	cfg, err := Load(writeConfig(t, `{
		"server": {},
		"kms": {
			"mode": "local",
			"local": {
				"master_key_env": "AEGIS_MASTER_KEY",
				"key_store_path": "aegis.keys"
			}
		},
		"providers": [{
			"id": "openai-primary",
			"api_key_id": "openai-key-1",
			"models": ["gpt-4o-mini"],
			"enabled": true
		}],
		"auth": {},
		"rate_limit": {},
		"egress": {"allowed_domains": ["api.openai.com"]}
	}`))
	if err != nil {
		t.Fatalf("Load canonical omissions: %v", err)
	}

	want := defaultConfig()
	if cfg.Server != want.Server {
		t.Fatalf("server defaults = %+v, want %+v", cfg.Server, want.Server)
	}
	if cfg.Auth != want.Auth {
		t.Fatalf("auth defaults = %+v, want %+v", cfg.Auth, want.Auth)
	}
	if cfg.RateLimit != want.RateLimit {
		t.Fatalf("rate-limit defaults = %+v, want %+v", cfg.RateLimit, want.RateLimit)
	}
	if cfg.KMS.Local.MinimumEnvelopeVersion != want.KMS.Local.MinimumEnvelopeVersion {
		t.Fatalf(
			"minimum envelope version = %d, want omitted-field default %d",
			cfg.KMS.Local.MinimumEnvelopeVersion,
			want.KMS.Local.MinimumEnvelopeVersion,
		)
	}
}

func TestLoadDoesNotEchoUnknownFieldOrInvalidDurationValues(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	tests := []struct {
		name   string
		data   []byte
		canary string
	}{
		{
			name:   "unknown field",
			data:   bytes.Replace(example, []byte(`"issuer": "aegis"`), []byte(`"CANARY_SECRET_FIELD_72b3": true, "issuer": "aegis"`), 1),
			canary: "CANARY_SECRET_FIELD_72b3",
		},
		{
			name:   "invalid duration string",
			data:   bytes.Replace(example, []byte(`"token_expiry": "24h"`), []byte(`"token_expiry": "CANARY_SECRET_DURATION_918a"`), 1),
			canary: "CANARY_SECRET_DURATION_918a",
		},
		{
			name:   "invalid duration type",
			data:   bytes.Replace(example, []byte(`"token_expiry": "24h"`), []byte(`"token_expiry": {"CANARY_SECRET_OBJECT_4d1c":true}`), 1),
			canary: "CANARY_SECRET_OBJECT_4d1c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "aegis.json")
			if err := os.WriteFile(path, tt.data, 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatal("Load accepted invalid config")
			}
			if strings.Contains(err.Error(), tt.canary) {
				t.Fatalf("Load error leaked canary %q: %v", tt.canary, err)
			}
		})
	}
}

func TestLoadRejectsOversizedConfigBeforeDecode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.json")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if err := file.Truncate(maxConfigFileBytes + 1); err != nil {
		_ = file.Close()
		t.Fatalf("Truncate: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err = Load(path)
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("Load oversized config error = %v, want size-limit rejection", err)
	}
}

func TestConfiguredRequestBodyLimitMatchesMandatorySemanticEnvelope(t *testing.T) {
	const semanticEnvelope int64 = 4 << 20
	if DefaultMaxRequestBodySize != semanticEnvelope || MaxRequestBodySizeLimit != semanticEnvelope {
		t.Fatalf(
			"request body defaults/max = %d/%d, want semantic envelope %d",
			DefaultMaxRequestBodySize,
			MaxRequestBodySizeLimit,
			semanticEnvelope,
		)
	}
}

func TestReadBoundedConfigFileRejectsGroupOrOtherWritableInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "writable.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	if _, err := readBoundedConfigFile(path); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("readBoundedConfigFile error = %v, want unsafe-permissions rejection", err)
	}
}

func TestLoadRejectsEmptyAuthIssuer(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	example = bytes.Replace(example, []byte(`"issuer": "aegis"`), []byte(`"issuer": ""`), 1)

	path := filepath.Join(t.TempDir(), "aegis.json")
	if err := os.WriteFile(path, example, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err = Load(path)
	if err == nil || !strings.Contains(err.Error(), "auth.issuer must not be empty") {
		t.Fatalf("Load error = %v, want empty issuer rejection", err)
	}
}

func TestLoadRejectsAuthIssuerAboveRevocationBound(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	example = bytes.Replace(
		example,
		[]byte(`"issuer": "aegis"`),
		[]byte(`"issuer": "`+strings.Repeat("i", 1025)+`"`),
		1,
	)
	path := filepath.Join(t.TempDir(), "aegis.json")
	if err := os.WriteFile(path, example, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err = Load(path)
	if err == nil || !strings.Contains(err.Error(), "auth.issuer must not exceed 1024 bytes") {
		t.Fatalf("Load error = %v, want revocable issuer bound", err)
	}
}

func TestLoadRejectsMissingLocalKMSKeyStorePath(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	example = bytes.Replace(example, []byte("      \"key_store_path\": \"aegis.keys\",\n"), nil, 1)

	path := filepath.Join(t.TempDir(), "aegis.json")
	if err := os.WriteFile(path, example, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err = Load(path)
	if err == nil || !strings.Contains(err.Error(), "kms.local.key_store_path must not be empty") {
		t.Fatalf("Load error = %v, want missing durable KMS path rejection", err)
	}
}

func TestLoadRejectsDisabledRateLimit(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	example = bytes.Replace(
		example,
		[]byte("\"rate_limit\": {\n    \"enabled\": true"),
		[]byte("\"rate_limit\": {\n    \"enabled\": false"),
		1,
	)

	path := filepath.Join(t.TempDir(), "aegis.json")
	if err := os.WriteFile(path, example, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err = Load(path)
	if err == nil || !strings.Contains(err.Error(), "rate_limit.enabled must be true") {
		t.Fatalf("Load error = %v, want disabled rate-limit rejection", err)
	}
}

func TestLoadRejectsZeroRateLimitBounds(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}

	tests := []struct {
		name    string
		old     string
		new     string
		wantErr string
	}{
		{name: "default RPM", old: `"default_rpm": 60`, new: `"default_rpm": 0`, wantErr: "rate_limit.default_rpm must be positive"},
		{name: "default concurrency", old: `"default_max_concurrency": 10`, new: `"default_max_concurrency": 0`, wantErr: "rate_limit.default_max_concurrency must be positive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := bytes.Replace(example, []byte(tt.old), []byte(tt.new), 1)
			path := filepath.Join(t.TempDir(), "aegis.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadRejectsMalformedEgressAllowlistEntries(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
	const canary = "CANARY-config-egress-secret-2b8e41"

	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	entries := []string{
		"https://api.openai.com",
		"https://user:" + canary + "@api.openai.com",
		"user@api.openai.com",
		"127.0.0.1",
		"*.openai.com:8443",
		"bad host",
	}
	for _, entry := range entries {
		t.Run(entry, func(t *testing.T) {
			data := bytes.Replace(example, []byte(`"api.openai.com"`), []byte(fmt.Sprintf("%q", entry)), 1)
			path := filepath.Join(t.TempDir(), "aegis.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), "egress.allowed_domains") {
				t.Fatalf("Load error = %v, want malformed egress allowlist rejection", err)
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatalf("Load error leaked malformed allowlist secret: %v", err)
			}
		})
	}
}

func TestLoadBindsLegacyLoopbackAllowlistToConfiguredProviderPorts(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	var document any
	if err := json.Unmarshal(example, &document); err != nil {
		t.Fatalf("decode example config: %v", err)
	}
	setConfigJSONValue(t, document, []any{"providers", 0, "base_url"}, "https://127.0.0.1:18443")
	setConfigJSONValue(t, document, []any{"providers", 1, "base_url"}, "https://127.0.0.1:28443")
	setConfigJSONValue(t, document, []any{"egress", "allowed_domains"}, []string{"127.0.0.1"})
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode loopback config: %v", err)
	}

	cfg, err := LoadForOperator(writeConfig(t, string(encoded)))
	if err != nil {
		t.Fatalf("LoadForOperator loopback compatibility config: %v", err)
	}
	if got, want := strings.Join(cfg.Egress.AllowedDomains, ","), "127.0.0.1:18443,127.0.0.1:28443"; got != want {
		t.Fatalf("bound loopback allowlist = %q, want %q", got, want)
	}
}

func TestLoadParsesDurationStrings(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	path := filepath.Join(t.TempDir(), "aegis.json")
	data := []byte(`{
			"server": {
				"address": ":9090",
				"read_timeout": "5s",
			"write_timeout": "2m",
			"shutdown_timeout": "10s",
			"max_request_body_size": 1024
		},
		"kms": {
			"mode": "local",
			"local": {
				"master_key_env": "AEGIS_MASTER_KEY",
				"key_store_path": "aegis.keys"
			}
		},
			"auth": {
				"jwt_signing_key_env": "AEGIS_JWT_KEY",
				"token_expiry": "24h",
				"issuer": "aegis"
			},
			"providers": [
				{
					"id": "openai-primary",
					"name": "OpenAI Primary",
					"type": "openai",
					"base_url": "https://api.openai.com",
					"api_key_id": "openai-key-1",
					"models": ["gpt-4o-mini"],
					"enabled": true
				}
			],
			"quota": {
				"enabled": false
			},
			"egress": {
				"allowed_domains": ["api.openai.com"]
			}
		}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Server.ReadTimeout != 5*time.Second {
		t.Fatalf("read timeout = %v, want 5s", cfg.Server.ReadTimeout)
	}
	if cfg.Server.WriteTimeout != 2*time.Minute {
		t.Fatalf("write timeout = %v, want 2m", cfg.Server.WriteTimeout)
	}
	if cfg.Auth.TokenExpiry != 24*time.Hour {
		t.Fatalf("token expiry = %v, want 24h", cfg.Auth.TokenExpiry)
	}
	if cfg.Server.MaxRequestBodySize != 1024 {
		t.Fatalf("max body size = %d, want 1024", cfg.Server.MaxRequestBodySize)
	}
	if cfg.KMS.Local.KeyStorePath != "aegis.keys" {
		t.Fatalf("key store path = %q, want aegis.keys", cfg.KMS.Local.KeyStorePath)
	}
	if cfg.KMS.Local.MinimumEnvelopeVersion != 2 {
		t.Fatalf("minimum envelope version = %d, want strict v2", cfg.KMS.Local.MinimumEnvelopeVersion)
	}
}

func TestLoadExampleConfig(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	cfg, err := Load(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("Load example config returned error: %v", err)
	}
	if cfg.RateLimit.DefaultTPM != 0 {
		t.Fatalf("example default_tpm = %d, want 0 (unlimited) by default", cfg.RateLimit.DefaultTPM)
	}
	if cfg.Auth.TokenExpiry > 24*time.Hour {
		t.Fatalf("example token expiry = %v, want no more than 24h for the standalone baseline", cfg.Auth.TokenExpiry)
	}
	if cfg.RateLimit.RedisURL != "" {
		t.Fatalf("example redis_url = %q, want empty until redis backend exists", cfg.RateLimit.RedisURL)
	}
	if cfg.KMS.Vault.Address != "" || cfg.KMS.Vault.Path != "" || cfg.KMS.Vault.TokenEnv != "" {
		t.Fatalf("example vault config = %+v, want empty until vault backend exists", cfg.KMS.Vault)
	}
	if cfg.KMS.Local.MinimumEnvelopeVersion != 2 {
		t.Fatalf("example minimum envelope version = %d, want 2", cfg.KMS.Local.MinimumEnvelopeVersion)
	}
	for _, provider := range cfg.Providers {
		if provider.MaxRPM != 0 {
			t.Fatalf("example provider %q max_rpm = %d, want 0 until provider RPM enforcement exists", provider.ID, provider.MaxRPM)
		}
	}
	if cfg.Quota.Enabled {
		t.Fatal("example config must keep quota disabled by default")
	}
	if cfg.Quota.Backend != "" || cfg.Quota.DSN != "" || cfg.Quota.DefaultBudget != 0 {
		t.Fatalf("example quota optional fields = backend=%q dsn=%q budget=%f, want empty/zero while quota is disabled", cfg.Quota.Backend, cfg.Quota.DSN, cfg.Quota.DefaultBudget)
	}
	if cfg.Admin.Enabled {
		t.Fatal("example config must keep admin disabled by default")
	}
	if cfg.Store.Type != "" || cfg.Store.DSN != "" {
		t.Fatalf("example store reserved fields = type=%q dsn=%q, want empty until control-plane store exists", cfg.Store.Type, cfg.Store.DSN)
	}
}

func TestLoadExampleConfigIncludesDurableFileRevocation(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	cfg, err := Load(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("Load example config returned error: %v", err)
	}
	if cfg.Auth.Revocation.Backend != "file" {
		t.Fatalf("revocation backend = %q, want file", cfg.Auth.Revocation.Backend)
	}
	if cfg.Auth.Revocation.FilePath != "aegis.revocations.json" {
		t.Fatalf("revocation file path = %q, want aegis.revocations.json", cfg.Auth.Revocation.FilePath)
	}
	if cfg.Auth.Revocation.RefreshInterval != 500*time.Millisecond {
		t.Fatalf("revocation refresh interval = %v, want 500ms", cfg.Auth.Revocation.RefreshInterval)
	}
}

func TestLoadForOperatorDoesNotRequireUnrelatedSecretEnvironment(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", "")

	cfg, err := LoadForOperator(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("LoadForOperator returned error without master-key env: %v", err)
	}
	if cfg.KMS.Local.MasterKeyEnv != "AEGIS_MASTER_KEY" {
		t.Fatalf("master key env = %q, want configured env name", cfg.KMS.Local.MasterKeyEnv)
	}
}

func TestDefaultConfigUsesTwentyFourHourTokenTTLAndFileRevocation(t *testing.T) {
	cfg := defaultConfig()
	if cfg.Auth.TokenExpiry != 24*time.Hour {
		t.Fatalf("default token expiry = %v, want 24h", cfg.Auth.TokenExpiry)
	}
	if cfg.Auth.Revocation.Backend != "file" || cfg.Auth.Revocation.FilePath == "" {
		t.Fatalf("default revocation = %+v, want durable file backend", cfg.Auth.Revocation)
	}
}

func TestLoadRejectsInvalidRevocationConfig(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}

	tests := []struct {
		name    string
		old     string
		new     string
		wantErr string
	}{
		{name: "backend", old: `"backend": "file"`, new: `"backend": "memory"`, wantErr: "unsupported auth.revocation backend"},
		{name: "empty path", old: `"file_path": "aegis.revocations.json"`, new: `"file_path": ""`, wantErr: "auth.revocation.file_path must not be empty"},
		{name: "too slow", old: `"refresh_interval": "500ms"`, new: `"refresh_interval": "10s"`, wantErr: "auth.revocation.refresh_interval must not exceed"},
		{name: "unknown field", old: `"backend": "file"`, new: `"backend": "file", "unknown": true`, wantErr: "unknown field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := bytes.Replace(example, []byte(tt.old), []byte(tt.new), 1)
			path := filepath.Join(t.TempDir(), "aegis.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateEnabledProviderIDsRejectsEmptyAndDuplicateIDs(t *testing.T) {
	tests := []struct {
		name      string
		providers []Provider
	}{
		{name: "empty", providers: []Provider{{Enabled: true, ID: ""}}},
		{name: "duplicate", providers: []Provider{{Enabled: true, ID: "same"}, {Enabled: true, ID: "same"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateEnabledProviderIDs(tt.providers); err == nil {
				t.Fatal("ValidateEnabledProviderIDs accepted invalid provider IDs")
			}
		})
	}
}

func TestLoadRejectsUnroutableEnabledProviderModelsWithoutLeakingMetadata(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}

	const (
		providerCanary = "provider-model-contract-canary-5f81"
		modelCanary    = "model-contract-canary-40c3"
	)
	tests := []struct {
		name   string
		mutate func(*testing.T, any)
	}{
		{
			name: "no enabled provider",
			mutate: func(t *testing.T, document any) {
				setConfigJSONValue(t, document, []any{"providers", 0, "enabled"}, false)
				setConfigJSONValue(t, document, []any{"providers", 1, "id"}, providerCanary)
				setConfigJSONValue(t, document, []any{"providers", 1, "enabled"}, false)
			},
		},
		{
			name: "enabled provider has no models",
			mutate: func(t *testing.T, document any) {
				setConfigJSONValue(t, document, []any{"providers", 1, "id"}, providerCanary)
				setConfigJSONValue(t, document, []any{"providers", 1, "models"}, []string{})
			},
		},
		{
			name: "enabled provider has empty model",
			mutate: func(t *testing.T, document any) {
				setConfigJSONValue(t, document, []any{"providers", 1, "id"}, providerCanary)
				setConfigJSONValue(t, document, []any{"providers", 1, "models"}, []string{""})
			},
		},
		{
			name: "enabled provider has whitespace-only model",
			mutate: func(t *testing.T, document any) {
				setConfigJSONValue(t, document, []any{"providers", 1, "id"}, providerCanary)
				setConfigJSONValue(t, document, []any{"providers", 1, "models"}, []string{" \t "})
			},
		},
		{
			name: "enabled provider model is not trim-stable",
			mutate: func(t *testing.T, document any) {
				setConfigJSONValue(t, document, []any{"providers", 1, "id"}, providerCanary)
				setConfigJSONValue(t, document, []any{"providers", 1, "models"}, []string{" " + modelCanary + " "})
			},
		},
		{
			name: "enabled provider has duplicate model",
			mutate: func(t *testing.T, document any) {
				setConfigJSONValue(t, document, []any{"providers", 1, "id"}, providerCanary)
				setConfigJSONValue(t, document, []any{"providers", 1, "models"}, []string{modelCanary, modelCanary})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var document any
			if err := json.Unmarshal(example, &document); err != nil {
				t.Fatalf("decode canonical config fixture: %v", err)
			}
			tt.mutate(t, document)
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatalf("encode config fixture: %v", err)
			}

			_, err = Load(writeConfig(t, string(data)))
			if err == nil {
				t.Fatal("Load accepted an enabled-provider model contract violation")
			}
			if strings.Contains(err.Error(), providerCanary) || strings.Contains(err.Error(), modelCanary) {
				t.Fatalf("Load error leaked provider or model metadata: %v", err)
			}
		})
	}
}

func TestValidateEnabledProviderModelsAllowsWildcardAndIgnoresDisabledProviders(t *testing.T) {
	providers := []Provider{
		{Enabled: true, Models: []string{"*"}},
		{Enabled: false, Models: []string{" ", "duplicate", "duplicate"}},
	}
	if err := ValidateEnabledProviderModels(providers); err != nil {
		t.Fatalf("ValidateEnabledProviderModels rejected supported model metadata: %v", err)
	}
}

func TestLoadRejectsInvalidMinimumEnvelopeVersion(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	data := bytes.Replace(example, []byte(`"minimum_envelope_version": 2`), []byte(`"minimum_envelope_version": 3`), 1)
	path := filepath.Join(t.TempDir(), "aegis.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "minimum_envelope_version must be 1 or 2") {
		t.Fatalf("Load error = %v, want envelope-version rejection", err)
	}
}

func TestLoadRejectsProviderAPIKeyIDAboveKMSBound(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	data := bytes.Replace(example, []byte(`"api_key_id": "openai-key-1"`), []byte(`"api_key_id": "`+strings.Repeat("k", 129)+`"`), 1)
	path := filepath.Join(t.TempDir(), "aegis.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "api_key_id must not exceed 128 bytes") {
		t.Fatalf("Load error = %v, want KMS key-ID bound rejection", err)
	}
}

func TestLoadAcceptsEnabledMemoryQuota(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	path := writeConfig(t, `{
		"kms": {
			"mode": "local",
			"local": {"master_key_env": "AEGIS_MASTER_KEY", "key_store_path": "aegis.keys"}
		},
		"providers": [
			{
				"id": "openai-primary",
				"name": "OpenAI Primary",
				"type": "openai",
				"base_url": "https://api.openai.com",
				"api_key_id": "openai-key-1",
				"models": ["gpt-4o-mini"],
				"enabled": true
			}
		],
		"quota": {"enabled": true, "backend": "memory", "default_budget": 10},
		"egress": {"allowed_domains": ["api.openai.com"]}
	}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load enabled memory quota: %v", err)
	}
	if !cfg.Quota.Enabled || cfg.Quota.DefaultBudget != 10 {
		t.Fatalf("quota = %+v, want enabled memory budget", cfg.Quota)
	}
}

func TestLoadRejectsReservedPersistenceConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "quota backend",
			config: `"quota": {
				"enabled": false,
				"backend": "sqlite"
			}`,
			wantErr: "quota.backend is reserved",
		},
		{
			name: "quota dsn",
			config: `"quota": {
				"enabled": false,
				"dsn": "aegis.db"
			}`,
			wantErr: "quota.dsn is reserved",
		},
		{
			name: "quota default budget",
			config: `"quota": {
				"enabled": false,
				"default_budget": 100.0
			}`,
			wantErr: "quota.default_budget requires quota.enabled=true",
		},
		{
			name: "quota model prices require enabled",
			config: `"quota": {
				"enabled": false,
				"model_prices": [{"model": "gpt-4o-mini", "input_per_million": 1, "output_per_million": 2}]
			}`,
			wantErr: "quota.model_prices requires quota.enabled=true",
		},
		{
			name: "store type",
			config: `"quota": {"enabled": false},
				"store": {
					"type": "sqlite"
				}`,
			wantErr: "store persistence config is reserved",
		},
		{
			name: "store dsn",
			config: `"quota": {"enabled": false},
				"store": {
					"dsn": "aegis.db"
				}`,
			wantErr: "store persistence config is reserved",
		},
		{
			name: "empty store field present",
			config: `"quota": {"enabled": false},
				"store": {}`,
			wantErr: "store persistence config is reserved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
			path := writeConfig(t, `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				`+tt.config+`,
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`)

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadRejectsNonPositiveAuthTokenExpiry(t *testing.T) {
	tests := []struct {
		name        string
		tokenExpiry string
	}{
		{name: "zero", tokenExpiry: "0s"},
		{name: "negative", tokenExpiry: "-1s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
			path := writeConfig(t, `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"auth": {
					"jwt_signing_key_env": "AEGIS_JWT_KEY",
					"token_expiry": "`+tt.tokenExpiry+`",
					"issuer": "aegis"
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`)

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), "auth.token_expiry must be positive") {
				t.Fatalf("Load error = %v, want auth.token_expiry failure", err)
			}
		})
	}
}

func TestLoadRejectsAuthTokenExpiryThatCannotBeRetained(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
	path := writeConfig(t, `{
		"kms": {"mode": "local", "local": {"master_key_env": "AEGIS_MASTER_KEY"}},
		"auth": {
			"jwt_signing_key_env": "AEGIS_JWT_KEY",
			"token_expiry": "2562047h47m16.854775807s",
			"issuer": "aegis"
		},
		"providers": [{
			"id": "openai-primary", "name": "OpenAI Primary", "type": "openai",
			"base_url": "https://api.openai.com", "api_key_id": "openai-key-1",
			"models": ["gpt-4o-mini"], "enabled": true
		}],
		"quota": {"enabled": false},
		"egress": {"allowed_domains": ["api.openai.com"]}
	}`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "maximum supported") {
		t.Fatalf("Load error = %v, want retained-lifetime bound", err)
	}
}

func TestLoadRejectsNonCanonicalAuthIssuerWhitespace(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	example = bytes.Replace(example, []byte(`"issuer": "aegis"`), []byte(`"issuer": " aegis "`), 1)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, example, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err = Load(path)
	if err == nil || !strings.Contains(err.Error(), "leading or trailing whitespace") {
		t.Fatalf("Load error = %v, want issuer whitespace rejection", err)
	}
}

func TestLoadRejectsInvalidServerBounds(t *testing.T) {
	tests := []struct {
		name    string
		server  string
		wantErr string
	}{
		{
			name:    "zero read timeout",
			server:  serverBoundsConfig("0s", "120s", "15s", DefaultMaxRequestBodySize),
			wantErr: "server.read_timeout must be positive",
		},
		{
			name:    "negative read timeout",
			server:  serverBoundsConfig("-1s", "120s", "15s", DefaultMaxRequestBodySize),
			wantErr: "server.read_timeout must be positive",
		},
		{
			name:    "zero write timeout",
			server:  serverBoundsConfig("30s", "0s", "15s", DefaultMaxRequestBodySize),
			wantErr: "server.write_timeout must be positive",
		},
		{
			name:    "negative write timeout",
			server:  serverBoundsConfig("30s", "-1s", "15s", DefaultMaxRequestBodySize),
			wantErr: "server.write_timeout must be positive",
		},
		{
			name:    "zero shutdown timeout",
			server:  serverBoundsConfig("30s", "120s", "0s", DefaultMaxRequestBodySize),
			wantErr: "server.shutdown_timeout must be positive",
		},
		{
			name:    "negative shutdown timeout",
			server:  serverBoundsConfig("30s", "120s", "-1s", DefaultMaxRequestBodySize),
			wantErr: "server.shutdown_timeout must be positive",
		},
		{
			name:    "zero body size",
			server:  serverBoundsConfig("30s", "120s", "15s", 0),
			wantErr: "server.max_request_body_size must be positive",
		},
		{
			name:    "negative body size",
			server:  serverBoundsConfig("30s", "120s", "15s", -1),
			wantErr: "server.max_request_body_size must be positive",
		},
		{
			name:    "body size above maximum",
			server:  serverBoundsConfig("30s", "120s", "15s", MaxRequestBodySizeLimit+1),
			wantErr: "server.max_request_body_size must not exceed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
			path := writeConfig(t, `{
				"server": {
					"address": ":9090",
					`+tt.server+`
				},
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`)

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadRejectsReservedRateControls(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "provider max_rpm",
			config: `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"max_rpm": 100,
						"enabled": true
					}
				],
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`,
			wantErr: "provider RPM enforcement is not implemented",
		},
		{
			name: "provider max_tpm",
			config: `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"max_tpm": 1000,
						"enabled": true
					}
				],
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`,
			wantErr: "TPM enforcement is not implemented",
		},
		{
			name: "redis url field present",
			config: `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				"rate_limit": {
					"enabled": true,
					"backend": "memory",
					"redis_url": ""
				},
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`,
			wantErr: "rate_limit.redis_url is reserved",
		},
		{
			name: "vault config field present",
			config: `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"},
					"vault": {}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`,
			wantErr: "kms.vault is reserved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
			path := writeConfig(t, tt.config)
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadAcceptsDefaultTPM(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
	path := writeConfig(t, `{
		"kms": {
			"mode": "local",
			"local": {"master_key_env": "AEGIS_MASTER_KEY", "key_store_path": "aegis.keys"}
		},
		"providers": [
			{
				"id": "openai-primary",
				"name": "OpenAI Primary",
				"type": "openai",
				"base_url": "https://api.openai.com",
				"api_key_id": "openai-key-1",
				"models": ["gpt-4o-mini"],
				"enabled": true
			}
		],
		"rate_limit": {
			"enabled": true,
			"backend": "memory",
			"default_rpm": 60,
			"default_tpm": 1000,
			"default_max_concurrency": 10
		},
		"quota": {"enabled": false},
		"egress": {"allowed_domains": ["api.openai.com"]}
	}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load default TPM: %v", err)
	}
	if cfg.RateLimit.DefaultTPM != 1000 {
		t.Fatalf("default_tpm = %d, want 1000", cfg.RateLimit.DefaultTPM)
	}
}

func TestLoadRejectsAdminNonLoopback(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
	path := writeConfig(t, `{
		"kms": {
			"mode": "local",
			"local": {"master_key_env": "AEGIS_MASTER_KEY", "key_store_path": "aegis.keys"}
		},
		"providers": [
			{
				"id": "openai-primary",
				"name": "OpenAI Primary",
				"type": "openai",
				"base_url": "https://api.openai.com",
				"api_key_id": "openai-key-1",
				"models": ["gpt-4o-mini"],
				"enabled": true
			}
		],
		"quota": {"enabled": false},
		"admin": {"enabled": true, "address": "0.0.0.0:9090", "token_env": "AEGIS_ADMIN_TOKEN"},
		"egress": {"allowed_domains": ["api.openai.com"]}
	}`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("Load error = %v, want loopback admin rejection", err)
	}
}

func TestLoadRejectsNegativeRateLimitValues(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "provider max_rpm",
			config: `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"max_rpm": -1,
						"enabled": true
					}
				],
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`,
			wantErr: "max_rpm must not be negative",
		},
		{
			name: "default_rpm",
			config: `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				"rate_limit": {
					"enabled": true,
					"backend": "memory",
					"default_rpm": -1
				},
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`,
			wantErr: "rate_limit.default_rpm must not be negative",
		},
		{
			name: "disabled default_rpm",
			config: `{
					"kms": {
						"mode": "local",
						"local": {"master_key_env": "AEGIS_MASTER_KEY"}
					},
					"providers": [
						{
							"id": "openai-primary",
							"name": "OpenAI Primary",
							"type": "openai",
							"base_url": "https://api.openai.com",
							"api_key_id": "openai-key-1",
							"models": ["gpt-4o-mini"],
							"enabled": true
						}
					],
					"rate_limit": {
						"enabled": false,
						"backend": "memory",
						"default_rpm": -1
					},
					"quota": {"enabled": false},
					"egress": {"allowed_domains": ["api.openai.com"]}
				}`,
			wantErr: "rate_limit.default_rpm must not be negative",
		},
		{
			name: "default_max_concurrency",
			config: `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				"rate_limit": {
					"enabled": true,
					"backend": "memory",
					"default_max_concurrency": -1
				},
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`,
			wantErr: "rate_limit.default_max_concurrency must not be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
			path := writeConfig(t, tt.config)

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadRejectsUnsupportedRuntimeBackends(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "redis",
			config: `"rate_limit": {
				"enabled": true,
				"backend": "redis"
			}`,
			wantErr: "redis rate limiter backend is not implemented",
		},
		{
			name: "disabled redis",
			config: `"rate_limit": {
					"enabled": false,
					"backend": "redis"
				}`,
			wantErr: "redis rate limiter backend is not implemented",
		},
		{
			name: "unknown rate limiter",
			config: `"rate_limit": {
				"enabled": true,
				"backend": "memcached"
			}`,
			wantErr: `unsupported rate_limit backend: "memcached"`,
		},
		{
			name: "vault",
			config: `"kms": {
				"mode": "vault"
			}`,
			wantErr: "vault KMS backend is not implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
			path := writeConfig(t, `{
				`+tt.config+`,
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`)

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func writeConfig(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "aegis.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const (
	nullCanaryServerValue   = "CANARY_NULL_SERVER_VALUE_3f8d"
	nullCanaryProviderValue = "CANARY_NULL_PROVIDER_VALUE_91c2"
)

func configWithNullAtPath(t *testing.T, data []byte, path []any) []byte {
	t.Helper()

	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode canonical config fixture: %v", err)
	}

	setConfigJSONValue(t, document, []any{"server", "tls", "ca_file"}, nullCanaryServerValue)
	setConfigJSONValue(t, document, []any{"providers", 1, "name"}, nullCanaryProviderValue)
	setConfigJSONValue(t, document, path, nil)

	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode null config fixture: %v", err)
	}
	return encoded
}

func setConfigJSONValue(t *testing.T, document any, path []any, value any) {
	t.Helper()
	if len(path) == 0 {
		t.Fatal("config JSON path must not be empty")
	}

	current := document
	for i, segment := range path {
		last := i == len(path)-1
		switch segment := segment.(type) {
		case string:
			object, ok := current.(map[string]any)
			if !ok {
				t.Fatalf("config JSON path segment %q does not address an object", segment)
			}
			if last {
				object[segment] = value
				return
			}

			next, exists := object[segment]
			if !exists || next == nil {
				if _, ok := path[i+1].(string); !ok {
					t.Fatalf("config JSON path segment %q cannot create a missing array", segment)
				}
				next = map[string]any{}
				object[segment] = next
			}
			current = next
		case int:
			array, ok := current.([]any)
			if !ok || segment < 0 || segment >= len(array) {
				t.Fatalf("config JSON path index %d is out of range", segment)
			}
			if last {
				array[segment] = value
				return
			}
			current = array[segment]
		default:
			t.Fatalf("unsupported config JSON path segment type %T", segment)
		}
	}
}

func serverBoundsConfig(readTimeout, writeTimeout, shutdownTimeout string, maxRequestBodySize int64) string {
	return fmt.Sprintf(`"read_timeout": %q,
		"write_timeout": %q,
		"shutdown_timeout": %q,
		"max_request_body_size": %d`, readTimeout, writeTimeout, shutdownTimeout, maxRequestBodySize)
}
