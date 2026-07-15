//go:build !darwin && !linux

package revocation

import (
	"context"
	"errors"
	"time"
)

func withFileLock(_ context.Context, _ string, _ time.Duration, _ func() error) error {
	return errors.New("durable local revocation writer is supported only on darwin and linux")
}
