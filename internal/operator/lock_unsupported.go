//go:build !darwin && !linux

package operator

import (
	"context"
	"errors"
	"time"
)

func withKMSFileLock(context.Context, string, time.Duration, func() error) error {
	return errors.New("KMS operator file locking is unsupported on this platform")
}
