//go:build !darwin && !linux

package revocation

import (
	"context"
	"errors"
	"os"
	"time"
)

func withFileLock(_ context.Context, _ string, _ time.Duration, _ func() error) error {
	return errors.New("durable local revocation writer is supported only on darwin and linux")
}

func openSnapshotNoFollow(string) (*os.File, error) {
	return nil, errors.New("secure revocation snapshot loading is supported only on darwin and linux")
}
