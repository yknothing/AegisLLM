//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	linuxMFDAllowSealing = 0x0002
	linuxMFDCloexec      = 0x0001
	linuxFAddSeals       = 1033
	linuxFGetSeals       = 1034
	linuxFSealSeal       = 0x0001
	linuxFSealShrink     = 0x0002
	linuxFSealGrow       = 0x0004
	linuxFSealWrite      = 0x0008
	requiredLinuxSeals   = linuxFSealSeal | linuxFSealShrink | linuxFSealGrow | linuxFSealWrite
)

// newSealableExecutable creates an anonymous Linux file whose contents can be
// made immutable before any release binary is inspected or executed.
func newSealableExecutable(label string) (*os.File, error) {
	sysMemfdCreate := linuxMemfdCreateSyscall()
	if sysMemfdCreate == 0 {
		return nil, errors.New("sealed release executables are unsupported on this Linux architecture")
	}
	name, err := syscall.BytePtrFromString("aegis-rollback-drill-" + label)
	if err != nil {
		return nil, err
	}
	fd, _, errno := syscall.Syscall(
		sysMemfdCreate,
		uintptr(unsafe.Pointer(name)), // #nosec G103 -- the kernel copies this NUL-terminated name during memfd_create.
		uintptr(linuxMFDCloexec|linuxMFDAllowSealing),
		0,
	)
	if errno != 0 {
		return nil, errno
	}
	file := os.NewFile(fd, "sealed-release-executable")
	if file == nil {
		_ = syscall.Close(int(fd))
		return nil, errors.New("opening memfd executable")
	}
	return file, nil
}

func linuxMemfdCreateSyscall() uintptr {
	switch runtime.GOARCH {
	case "amd64":
		return 319
	case "arm64":
		return 279
	default:
		return 0
	}
}

// sealAndReopenExecutable makes a completed memfd executable immutable, then
// returns a read-only descriptor for all subsequent identity checks and execs.
func sealAndReopenExecutable(writable *os.File) (*os.File, error) {
	if writable == nil {
		return nil, errors.New("nil memfd executable")
	}
	fd := int(writable.Fd())
	if err := syscall.Fchmod(fd, 0o500); err != nil { // #nosec G302 -- the sealed snapshot is intentionally owner-executable.
		return nil, err
	}
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(linuxFAddSeals), uintptr(requiredLinuxSeals))
	if errno != 0 {
		return nil, errno
	}
	if err := verifyExecutableSeals(writable); err != nil {
		return nil, err
	}
	readFD, err := syscall.Open(fmt.Sprintf("/proc/self/fd/%d", fd), syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	readOnly := os.NewFile(uintptr(readFD), "sealed-release-executable-readonly")
	if readOnly == nil {
		_ = syscall.Close(readFD)
		return nil, errors.New("reopening sealed executable")
	}
	writableInfo, writableErr := writable.Stat()
	readOnlyInfo, readOnlyErr := readOnly.Stat()
	if writableErr != nil || readOnlyErr != nil || !os.SameFile(writableInfo, readOnlyInfo) {
		_ = readOnly.Close()
		return nil, errors.New("sealed executable descriptor identity mismatch")
	}
	if err := verifyExecutableSeals(readOnly); err != nil {
		_ = readOnly.Close()
		return nil, err
	}
	return readOnly, nil
}

func verifyExecutableSeals(file *os.File) error {
	if file == nil {
		return errors.New("nil sealed executable")
	}
	seals, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), uintptr(linuxFGetSeals), 0)
	if errno != 0 {
		return errno
	}
	if int(seals)&requiredLinuxSeals != requiredLinuxSeals {
		return errors.New("required executable seals are missing")
	}
	return nil
}

func commandForSealedExecutable(file *os.File, args ...string) (*exec.Cmd, error) {
	if err := verifyExecutableSeals(file); err != nil {
		return nil, err
	}
	cmd := exec.Command("/proc/self/fd/3", args...) // #nosec G204 -- fd 3 is the immutable executable supplied below; no shell or caller path is used.
	cmd.ExtraFiles = []*os.File{file}
	return cmd, nil
}
