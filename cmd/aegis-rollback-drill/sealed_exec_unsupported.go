//go:build !linux

package main

import (
	"errors"
	"os"
	"os/exec"
)

var errSealedExecutableUnsupported = errors.New("sealed release executables require Linux memfd sealing")

func newSealableExecutable(string) (*os.File, error) {
	return nil, errSealedExecutableUnsupported
}

func sealAndReopenExecutable(*os.File) (*os.File, error) {
	return nil, errSealedExecutableUnsupported
}

func verifyExecutableSeals(*os.File) error {
	return errSealedExecutableUnsupported
}

func commandForSealedExecutable(*os.File, ...string) (*exec.Cmd, error) {
	return nil, errSealedExecutableUnsupported
}
