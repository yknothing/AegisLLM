//go:build linux

package main

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// linuxOpenPath is O_PATH from the Linux UAPI. Go 1.22's syscall package does
// not expose it, but the flag value is stable across supported Linux targets.
const linuxOpenPath = 0x200000

func openFileAt(directory *os.File, name string, flags int, mode uint32) (*os.File, error) {
	if directory == nil || name == "" {
		return nil, errors.New("directory and entry name are required")
	}
	fd, err := syscall.Openat(int(directory.Fd()), name, flags, mode)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "drill-owner-only-entry")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("opening directory entry")
	}
	return file, nil
}

func readlinkAt(directory *os.File, name string, maxBytes int) ([]byte, error) {
	if directory == nil || name == "" || maxBytes < 1 {
		return nil, errors.New("directory, entry name, and positive limit are required")
	}
	namePointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, maxBytes+1)
	n, _, errno := syscall.Syscall6(
		syscall.SYS_READLINKAT,
		directory.Fd(),
		uintptr(unsafe.Pointer(namePointer)), // #nosec G103 -- readlinkat copies this bounded NUL-terminated basename.
		uintptr(unsafe.Pointer(&buffer[0])),  // #nosec G103 -- the kernel writes at most the explicitly supplied buffer length.
		uintptr(len(buffer)),
		0,
		0,
	)
	runtime.KeepAlive(namePointer)
	runtime.KeepAlive(buffer)
	if errno != 0 {
		return nil, errno
	}
	if n > uintptr(maxBytes) {
		return nil, errors.New("symbolic link target exceeds limit")
	}
	return buffer[:int(n)], nil
}

func entryInfoAt(directory *os.File, name string, _ os.FileMode) (os.FileInfo, error) {
	file, err := openFileAt(directory, name, linuxOpenPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return file.Stat()
}
