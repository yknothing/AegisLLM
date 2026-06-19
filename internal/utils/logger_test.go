package utils

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestSafeHandlerRedactsSensitiveTopLevelAttrs(t *testing.T) {
	var out bytes.Buffer
	logger := NewAuditLogger(&out, slog.LevelInfo)

	logger.Info("request completed",
		"authorization", "Bearer sk-secret",
		"prompt", "user prompt",
		"status", 200,
	)

	logOutput := out.String()
	for _, forbidden := range []string{"Bearer sk-secret", "user prompt"} {
		if strings.Contains(logOutput, forbidden) {
			t.Fatalf("log output leaked %q: %s", forbidden, logOutput)
		}
	}
	if strings.Count(logOutput, "[REDACTED]") != 2 {
		t.Fatalf("log output = %s, want two redacted fields", logOutput)
	}
	if !strings.Contains(logOutput, `"status":200`) {
		t.Fatalf("log output = %s, want non-sensitive metadata preserved", logOutput)
	}
}

func TestSafeHandlerPreservesSafeStructuralTokenCounts(t *testing.T) {
	var out bytes.Buffer
	logger := NewAuditLogger(&out, slog.LevelInfo)

	logger.Info("request completed",
		"prompt", "user prompt",
		"prompt_tokens", 7,
		"completion_tokens", 11,
		"total_tokens", 18,
	)

	logOutput := out.String()
	if strings.Contains(logOutput, "user prompt") {
		t.Fatalf("log output leaked prompt content: %s", logOutput)
	}
	for _, want := range []string{`"prompt_tokens":7`, `"completion_tokens":11`, `"total_tokens":18`} {
		if !strings.Contains(logOutput, want) {
			t.Fatalf("log output = %s, want structural field %s preserved", logOutput, want)
		}
	}
}

func TestSafeHandlerRedactsNestedGroupAttrs(t *testing.T) {
	var out bytes.Buffer
	logger := NewAuditLogger(&out, slog.LevelInfo)

	logger.Info("request completed",
		slog.Group("request",
			slog.String("body", "secret prompt"),
			slog.String("X-Api-Key", "sk-nested"),
			slog.Int("status", 200),
		),
	)

	logOutput := out.String()
	for _, forbidden := range []string{"secret prompt", "sk-nested"} {
		if strings.Contains(logOutput, forbidden) {
			t.Fatalf("nested log output leaked %q: %s", forbidden, logOutput)
		}
	}
	if strings.Count(logOutput, "[REDACTED]") != 2 {
		t.Fatalf("log output = %s, want two nested redacted fields", logOutput)
	}
	if !strings.Contains(logOutput, `"status":200`) {
		t.Fatalf("log output = %s, want nested non-sensitive metadata preserved", logOutput)
	}
}

func TestSafeHandlerRedactsWithAttrs(t *testing.T) {
	var out bytes.Buffer
	handler := NewSafeHandler(slog.NewJSONHandler(&out, nil))
	logger := slog.New(handler.WithAttrs([]slog.Attr{
		slog.String("client_secret", "client-secret-value"),
		slog.String("component", "gateway"),
	}))

	logger.Info("startup")

	logOutput := out.String()
	if strings.Contains(logOutput, "client-secret-value") {
		t.Fatalf("WithAttrs log output leaked secret: %s", logOutput)
	}
	if !strings.Contains(logOutput, "[REDACTED]") {
		t.Fatalf("log output = %s, want redacted WithAttrs secret", logOutput)
	}
	if !strings.Contains(logOutput, `"component":"gateway"`) {
		t.Fatalf("log output = %s, want non-sensitive WithAttrs metadata preserved", logOutput)
	}
}

type requestLogValue struct{}

func (requestLogValue) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("body", "deferred secret prompt"),
		slog.String("method", "POST"),
	)
}

func TestSafeHandlerRedactsResolvedLogValuerGroups(t *testing.T) {
	var out bytes.Buffer
	logger := NewAuditLogger(&out, slog.LevelInfo)

	logger.Info("request completed", slog.Any("request", requestLogValue{}))

	logOutput := out.String()
	if strings.Contains(logOutput, "deferred secret prompt") {
		t.Fatalf("LogValuer group leaked secret: %s", logOutput)
	}
	if !strings.Contains(logOutput, "[REDACTED]") {
		t.Fatalf("log output = %s, want redacted LogValuer group secret", logOutput)
	}
	if !strings.Contains(logOutput, `"method":"POST"`) {
		t.Fatalf("log output = %s, want non-sensitive LogValuer metadata preserved", logOutput)
	}
}
