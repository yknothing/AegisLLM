//go:build darwin || linux

package server

import (
	"os"
	"syscall"
)

func openTLSFileNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- the configured TLS path is opened read-only; O_NOFOLLOW rejects a final-component symlink atomically and O_NONBLOCK prevents special files from stalling startup before fstat.
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
