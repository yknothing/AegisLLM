//go:build darwin

package main

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	darwinSYSOpenat     = 0x2000000 + 463
	darwinSYSReadlinkat = 0x2000000 + 473
)

func openFileAt(directory *os.File, name string, flags int, mode uint32) (*os.File, error) {
	if directory == nil || name == "" {
		return nil, errors.New("directory and entry name are required")
	}
	namePointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	fd, _, errno := syscall.Syscall6(
		darwinSYSOpenat,
		directory.Fd(),
		uintptr(unsafe.Pointer(namePointer)), // #nosec G103 -- openat copies this bounded NUL-terminated basename.
		uintptr(flags),
		uintptr(mode),
		0,
		0,
	)
	runtime.KeepAlive(namePointer)
	if errno != 0 {
		return nil, errno
	}
	file := os.NewFile(fd, "drill-owner-only-entry")
	if file == nil {
		_ = syscall.Close(int(fd))
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
		darwinSYSReadlinkat,
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
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_SYMLINK
	file, err := openFileAt(directory, name, flags, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return file.Stat()
}
