package runtime

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yknothing/AegisLLM/internal/gatewayconst"
)

const (
	liftLiteLLMBinEnv         = "AEGIS_LIFT_LITELLM"
	liftLiteLLMHost           = "127.0.0.1"
	liftLiteLLMAPIKey         = "sk-mock"
	liftLiteLLMHealthPath     = "/health/liveliness"
	liftLiteLLMHealthAttempts = 200
	liftLiteLLMHealthRetry    = 50 * time.Millisecond
	liftLiteLLMNumRetries     = 0
	liftLiteLLMWorkers        = 1
	liftLiteLLMConfigMode     = 0o600
	liftOpenAIAPIBaseSuffix   = "/v1"
	liftBenchOKJSON           = `{"id":"chatcmpl-lift","object":"chat.completion","created":1,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
)

// TestRuntimeSameBoxLiteLLMOverhead measures Aegis and LiteLLM Proxy against one TLS mock.
func TestRuntimeSameBoxLiteLLMOverhead(t *testing.T) {
	litellmBin := os.Getenv(liftLiteLLMBinEnv)
	if strings.TrimSpace(litellmBin) == "" {
		t.Skipf("%s is unset; this test records the same-box protocol and is skipped in CI", liftLiteLLMBinEnv)
	}
	if _, err := os.Stat(litellmBin); err != nil {
		t.Fatalf("LiteLLM executable %q is not usable: %v", litellmBin, err)
	}

	env := startLiftRuntime(t, liftRuntimeOptions{
		defaultRPM:     liftOverheadDefaultRPM,
		maxConcurrency: liftOverheadMaxConcurrency,
		providers: []liftProvider{{
			id:       liftPrimaryProviderID,
			keyID:    liftPrimaryKeyID,
			secret:   liftPrimarySecret,
			priority: liftPrimaryPriority,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", gatewayconst.JSONContentType)
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, liftBenchOKJSON)
			},
		}},
	})
	defer env.stop(t)

	litellmURL, litellmPID := startLiftLiteLLMProxy(t, litellmBin, env.mockURL)
	aegisToken := env.token(t, liftOverheadDefaultRPM, liftOverheadMaxConcurrency)

	aegisSamples := benchGateway(t, func() (*http.Response, []byte) {
		return liftChatWithToken(t, env, aegisToken, liftChatJSON)
	})
	litellmSamples := benchGateway(t, func() (*http.Response, []byte) {
		return liftPostJSON(t, env.client, litellmURL+gatewayconst.PathChatCompletions, liftChatJSON)
	})

	aegisRSS := processRSSKiB(t, os.Getpid())
	litellmRSS := processRSSKiB(t, litellmPID)
	aegisP95 := durationPercentile(aegisSamples, liftPercentileP95)
	litellmP95 := durationPercentile(litellmSamples, liftPercentileP95)
	t.Logf(
		"same_box_overhead collected_at=%s n=%d aegis_p50=%s aegis_p95=%s aegis_p99=%s aegis_rss_kib=%d litellm_p50=%s litellm_p95=%s litellm_p99=%s litellm_rss_kib=%d",
		time.Now().UTC().Format(time.RFC3339),
		liftOverheadSamples,
		durationPercentile(aegisSamples, liftPercentileP50),
		aegisP95,
		durationPercentile(aegisSamples, liftPercentileP99),
		aegisRSS,
		durationPercentile(litellmSamples, liftPercentileP50),
		litellmP95,
		durationPercentile(litellmSamples, liftPercentileP99),
		litellmRSS,
	)
	if aegisP95 > litellmP95 {
		t.Logf("protocol_pass=false reason=aegis_p95_worse")
	} else {
		t.Logf("protocol_pass=true")
	}
}

// startLiftLiteLLMProxy launches OSS LiteLLM against the shared mock upstream.
func startLiftLiteLLMProxy(t *testing.T, bin, mockURL string) (baseURL string, pid int) {
	t.Helper()
	listenAddr := reserveLoopbackAddr(t)
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		t.Fatalf("parse LiteLLM listen address: %v", err)
	}
	configPath := writeLiftLiteLLMConfig(t, mockURL+liftOpenAIAPIBaseSuffix)
	logPath := filepath.Join(t.TempDir(), "litellm.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create LiteLLM log: %v", err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	t.Cleanup(func() {
		if t.Failed() {
			dump, readErr := os.ReadFile(logPath)
			if readErr == nil {
				t.Logf("litellm log:\n%s", dump)
			}
		}
	})

	cmd := exec.Command(bin,
		"--config", configPath,
		"--host", liftLiteLLMHost,
		"--port", port,
		"--telemetry", "False",
		"--num_workers", strconv.Itoa(liftLiteLLMWorkers),
	)
	cmd.Env = liftLiteLLMProcessEnv()
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start LiteLLM: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	baseURL = "http://" + net.JoinHostPort(liftLiteLLMHost, port)
	client := &http.Client{Timeout: liftClientTimeout}
	waitHTTPStatusAttempts(t, client, baseURL+liftLiteLLMHealthPath, nil, http.StatusOK, liftLiteLLMHealthAttempts, liftLiteLLMHealthRetry)
	return baseURL, cmd.Process.Pid
}

// writeLiftLiteLLMConfig writes a loopback-only Proxy YAML with retries disabled.
func writeLiftLiteLLMConfig(t *testing.T, apiBase string) string {
	t.Helper()
	body := fmt.Sprintf(`model_list:
  - model_name: %s
    litellm_params:
      model: %s/%s
      api_base: %s
      api_key: %s
litellm_settings:
  ssl_verify: false
  drop_params: true
  num_retries: %d
general_settings:
  disable_spend_logs: true
`, liftChatModel, gatewayconst.ProviderTypeOpenAI, liftChatModel, apiBase, liftLiteLLMAPIKey, liftLiteLLMNumRetries)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), liftLiteLLMConfigMode); err != nil {
		t.Fatalf("write LiteLLM config: %v", err)
	}
	return path
}

func liftLiteLLMProcessEnv() []string {
	drop := map[string]struct{}{
		"ALL_PROXY":   {},
		"all_proxy":   {},
		"HTTPS_PROXY": {},
		"HTTP_PROXY":  {},
		"https_proxy": {},
		"http_proxy":  {},
	}
	out := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		if _, skip := drop[key]; skip {
			continue
		}
		out = append(out, kv)
	}
	out = append(out,
		"SSL_VERIFY=False",
		"NO_PROXY=127.0.0.1,localhost,::1",
		"no_proxy=127.0.0.1,localhost,::1",
	)
	return out
}

func benchGateway(t *testing.T, roundTrip func() (*http.Response, []byte)) []time.Duration {
	t.Helper()
	for i := 0; i < liftOverheadWarmup; i++ {
		resp, body := roundTrip()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("warmup status = %d body=%s, want 200", resp.StatusCode, body)
		}
	}
	samples := make([]time.Duration, 0, liftOverheadSamples)
	for i := 0; i < liftOverheadSamples; i++ {
		started := time.Now()
		resp, body := roundTrip()
		elapsed := time.Since(started)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("sample status = %d body=%s, want 200", resp.StatusCode, body)
		}
		samples = append(samples, elapsed)
	}
	return samples
}

func liftPostJSON(t *testing.T, client *http.Client, rawURL, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build post: %v", err)
	}
	req.Header.Set("Content-Type", gatewayconst.JSONContentType)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", rawURL, err)
	}
	payload, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read post response: %v", readErr)
	}
	return resp, payload
}

func processRSSKiB(t *testing.T, pid int) int64 {
	t.Helper()
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		t.Fatalf("ps rss for pid %d: %v", pid, err)
	}
	kib, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		t.Fatalf("parse rss %q: %v", out, err)
	}
	return kib
}
