//go:build !darwin && !linux

package config

import (
	"errors"
	"os"
)

func openConfigNoFollow(string) (*os.File, error) {
	return nil, errors.New("secure config loading is supported only on darwin and linux")
}
