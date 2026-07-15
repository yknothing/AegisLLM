//go:build darwin || linux

package operator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

func withKMSFileLock(ctx context.Context, path string, timeout time.Duration, action func() error) error {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("opening KMS operator lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { _ = file.Close() }()
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("setting KMS operator lock permissions: %w", err)
	}

	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			defer func() { _ = syscall.Flock(fd, syscall.LOCK_UN) }()
			return action()
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return fmt.Errorf("acquiring KMS operator lock: %w", err)
		}
		if time.Now().After(deadline) {
			return errors.New("timed out acquiring KMS operator lock")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
