//go:build !darwin && !linux

package server

import (
	"errors"
	"os"
)

func openTLSFileNoFollow(string) (*os.File, error) {
	return nil, errors.New("secure TLS file loading is unsupported on this platform")
}
