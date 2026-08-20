//go:build !linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotExecutableFailsClosedOutsideLinux(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidate")
	if err := os.WriteFile(path, []byte("not-an-executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	executable, _, err := snapshotExecutable(path, "candidate")
	if executable != nil {
		_ = executable.close()
		t.Fatal("snapshotExecutable returned an executable on an unsupported host")
	}
	if err == nil {
		t.Fatal("snapshotExecutable did not fail closed outside Linux")
	}
}
