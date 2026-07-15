package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/yknothing/AegisLLM/internal/config"
	operatorservice "github.com/yknothing/AegisLLM/internal/operator"
	"github.com/yknothing/AegisLLM/internal/utils"
)

const maxProviderKeyBytes = 16 << 10

func runOperator(args []string, stdin io.Reader, stdinIsTTY bool, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		printOperatorUsage(stdout)
		return 0
	}
	if len(args) < 2 {
		printOperatorUsage(stderr)
		return 2
	}
	var err error
	switch args[0] + " " + args[1] {
	case "revocation init":
		err = runRevocationInit(args[2:], stdout, stderr)
	case "provider-key import":
		err = runProviderKeyImport(args[2:], stdin, stdinIsTTY, stdout, stderr)
	case "virtual-key issue":
		err = runVirtualKeyIssue(args[2:], stdout, stderr)
	case "virtual-key revoke":
		err = runVirtualKeyRevoke(args[2:], stdout, stderr)
	case "kms migrate":
		err = runKMSMigrate(args[2:], stdout, stderr)
	default:
		printOperatorUsage(stderr)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "operator error: %v\n", err)
		return 1
	}
	return 0
}

func runRevocationInit(args []string, _ io.Writer, stderr io.Writer) error {
	flags := newOperatorFlagSet("revocation init", stderr)
	configPath := flags.String("config", "", "path to configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := rejectPositionalArgs(flags); err != nil {
		return err
	}
	service, _, err := loadOperatorService(*configPath)
	if err != nil {
		return err
	}
	result, err := service.InitRevocation(context.Background())
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stderr, "revocation_initialized generation=%d changed=%t\n", result.Generation, result.Changed)
	return nil
}

func runProviderKeyImport(args []string, stdin io.Reader, stdinIsTTY bool, _ io.Writer, stderr io.Writer) error {
	flags := newOperatorFlagSet("provider-key import", stderr)
	configPath := flags.String("config", "", "path to configuration file")
	providerID := flags.String("provider", "", "enabled provider ID")
	replace := flags.Bool("replace", false, "replace an existing provider key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := rejectPositionalArgs(flags); err != nil {
		return err
	}
	if stdinIsTTY {
		return errors.New("provider key stdin must be redirected; terminal input is not accepted")
	}
	if strings.TrimSpace(*providerID) == "" {
		return errors.New("--provider is required")
	}
	buffer := make([]byte, maxProviderKeyBytes+1)
	defer utils.MemZero(buffer)
	n, err := io.ReadFull(stdin, buffer)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return errors.New("reading provider key from stdin")
	}
	plaintext := buffer[:n]
	if len(plaintext) > maxProviderKeyBytes {
		return fmt.Errorf("provider key exceeds %d-byte size limit", maxProviderKeyBytes)
	}
	plaintext = trimOneLineEnding(plaintext)
	if len(plaintext) == 0 {
		return errors.New("provider key stdin is empty")
	}
	if bytes.IndexByte(plaintext, 0) >= 0 {
		return errors.New("provider key stdin contains a NUL byte")
	}
	service, _, err := loadOperatorService(*configPath)
	if err != nil {
		return err
	}
	if err := service.ImportProviderKey(context.Background(), *providerID, plaintext, *replace); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stderr, "provider_key_imported provider=%s replaced=%t\n", *providerID, *replace)
	return nil
}

func runVirtualKeyIssue(args []string, stdout, stderr io.Writer) error {
	flags := newOperatorFlagSet("virtual-key issue", stderr)
	configPath := flags.String("config", "", "path to configuration file")
	subject := flags.String("subject", "", "virtual-key subject")
	modelsCSV := flags.String("models", "", "comma-separated configured models")
	ttl := flags.Duration("ttl", 0, "token lifetime, bounded by auth.token_expiry")
	maxRPM := flags.Int("rpm", 0, "per-key requests per minute")
	maxConcurrency := flags.Int("max-concurrency", 0, "per-key concurrent request limit")
	outPath := flags.String("out", "", "new owner-only token output file")
	toStdout := flags.Bool("stdout", false, "write only the token to stdout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := rejectPositionalArgs(flags); err != nil {
		return err
	}
	if (*outPath == "") == !*toStdout {
		return errors.New("choose exactly one of --out or --stdout")
	}
	service, _, err := loadOperatorService(*configPath)
	if err != nil {
		return err
	}
	token, claims, err := service.IssueVirtualKey(operatorservice.IssueOptions{
		Subject:        *subject,
		Models:         splitCSV(*modelsCSV),
		TTL:            *ttl,
		MaxRPM:         *maxRPM,
		MaxConcurrency: *maxConcurrency,
	})
	if err != nil {
		return err
	}
	if *toStdout {
		if _, err := fmt.Fprintln(stdout, token); err != nil {
			return errors.New("writing virtual key to stdout")
		}
	} else if err := writeSecretFileExclusive(*outPath, token); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stderr, "virtual_key_issued kid=%s expires_at=%d\n", claims.KeyID, claims.ExpiresAt)
	return nil
}

func runVirtualKeyRevoke(args []string, _ io.Writer, stderr io.Writer) error {
	flags := newOperatorFlagSet("virtual-key revoke", stderr)
	configPath := flags.String("config", "", "path to configuration file")
	keyID := flags.String("kid", "", "virtual-key ID")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := rejectPositionalArgs(flags); err != nil {
		return err
	}
	if strings.TrimSpace(*keyID) == "" {
		return errors.New("--kid is required")
	}
	service, cfg, err := loadOperatorService(*configPath)
	if err != nil {
		return err
	}
	result, err := service.RevokeVirtualKey(context.Background(), *keyID)
	if err != nil {
		return err
	}
	visibleBy := time.Now().Add(cfg.Auth.Revocation.RefreshInterval + 250*time.Millisecond).UTC()
	_, _ = fmt.Fprintf(stderr, "virtual_key_revoked kid=%s generation=%d changed=%t visible_by=%s\n",
		*keyID, result.Generation, result.Changed, visibleBy.Format(time.RFC3339Nano))
	return nil
}

func runKMSMigrate(args []string, _ io.Writer, stderr io.Writer) error {
	flags := newOperatorFlagSet("kms migrate", stderr)
	configPath := flags.String("config", "", "path to configuration file")
	dryRun := flags.Bool("dry-run", false, "validate and report without writing")
	apply := flags.Bool("apply", false, "back up and migrate legacy blobs")
	backupDir := flags.String("backup-dir", "", "new directory for encrypted pre-migration blobs")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := rejectPositionalArgs(flags); err != nil {
		return err
	}
	if *dryRun == *apply {
		return errors.New("choose exactly one of --dry-run or --apply")
	}
	service, _, err := loadOperatorService(*configPath)
	if err != nil {
		return err
	}
	var report struct{ Total, Legacy, V2, Migrated int }
	var operationErr error
	if *dryRun {
		got, err := service.InspectKMS(context.Background())
		report.Total, report.Legacy, report.V2, report.Migrated = got.Total, got.Legacy, got.V2, got.Migrated
		operationErr = err
	} else {
		got, err := service.MigrateKMS(context.Background(), *backupDir)
		report.Total, report.Legacy, report.V2, report.Migrated = got.Total, got.Legacy, got.V2, got.Migrated
		operationErr = err
	}
	_, _ = fmt.Fprintf(stderr, "kms_migration total=%d legacy=%d v2=%d migrated=%d dry_run=%t\n",
		report.Total, report.Legacy, report.V2, report.Migrated, *dryRun)
	if operationErr != nil {
		return fmt.Errorf("KMS migration failed after migrated=%d: %w", report.Migrated, operationErr)
	}
	return nil
}

func newOperatorFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	return flags
}

func rejectPositionalArgs(flags *flag.FlagSet) error {
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	return nil
}

func loadOperatorService(configPath string) (*operatorservice.Service, *config.Config, error) {
	if strings.TrimSpace(configPath) == "" {
		return nil, nil, errors.New("--config is required for operator commands")
	}
	cfg, err := config.LoadForOperator(configPath)
	if err != nil {
		return nil, nil, err
	}
	service, err := operatorservice.New(cfg)
	return service, cfg, err
}

func trimOneLineEnding(value []byte) []byte {
	if len(value) > 0 && value[len(value)-1] == '\n' {
		value = value[:len(value)-1]
		if len(value) > 0 && value[len(value)-1] == '\r' {
			value = value[:len(value)-1]
		}
	}
	return value
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func writeSecretFileExclusive(path, token string) (err error) {
	if strings.TrimSpace(path) == "" {
		return errors.New("virtual-key output path must not be empty")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) // #nosec G304 -- explicit operator-selected output path.
	if err != nil {
		return fmt.Errorf("creating exclusive virtual-key output: %w", err)
	}
	removeOnFailure := true
	defer func() {
		_ = file.Close()
		if removeOnFailure {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("setting virtual-key output permissions: %w", err)
	}
	if _, err := io.WriteString(file, token+"\n"); err != nil {
		return errors.New("writing virtual-key output")
	}
	if err := file.Sync(); err != nil {
		return errors.New("syncing virtual-key output")
	}
	if err := file.Close(); err != nil {
		return errors.New("closing virtual-key output")
	}
	removeOnFailure = false
	return nil
}

func printOperatorUsage(w io.Writer) {
	_, _ = io.WriteString(w, `usage: aegis operator <command> [flags]

commands:
  revocation init
  provider-key import
  virtual-key issue
  virtual-key revoke
  kms migrate
`)
}
