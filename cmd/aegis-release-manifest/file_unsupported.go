//go:build !darwin && !linux

package main

import (
	"errors"
	"os"
)

func openEvidenceFile(string) (*os.File, error) {
	return nil, errors.New("secure release evidence loading is unsupported on this operating system")
}
