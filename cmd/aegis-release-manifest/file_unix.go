//go:build darwin || linux

package main

import (
	"errors"
	"os"
	"syscall"
)

func openEvidenceFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- the explicit evidence path is opened without following links and validated on the same descriptor.
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "release-evidence-input")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("opening release evidence input")
	}
	return file, nil
}
