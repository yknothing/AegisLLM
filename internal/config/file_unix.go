//go:build darwin || linux

package config

import (
	"os"
	"syscall"
)

func openConfigNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- the caller-supplied config path is opened atomically without following a final symlink or blocking on a special file.
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, syscall.EBADF
	}
	return file, nil
}
