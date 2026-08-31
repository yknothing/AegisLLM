//go:build !linux && !darwin

package main

import (
	"errors"
	"os"
)

func openFileAt(*os.File, string, int, uint32) (*os.File, error) {
	return nil, errors.New("descriptor-relative file access is unsupported on this platform")
}

func readlinkAt(*os.File, string, int) ([]byte, error) {
	return nil, errors.New("descriptor-relative symbolic-link access is unsupported on this platform")
}

func entryInfoAt(*os.File, string, os.FileMode) (os.FileInfo, error) {
	return nil, errors.New("descriptor-relative metadata access is unsupported on this platform")
}
