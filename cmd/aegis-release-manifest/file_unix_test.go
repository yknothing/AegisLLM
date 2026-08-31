//go:build darwin || linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestReadBoundedRegularFileRejectsUnsafeFileTypesAndPermissions(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(regular, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	symlink := filepath.Join(root, "manifest-link.json")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := readBoundedRegularFile(symlink); err == nil {
		t.Fatal("readBoundedRegularFile followed a symlink")
	}

	fifo := filepath.Join(root, "manifest.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	if _, err := readBoundedRegularFile(fifo); err == nil {
		t.Fatal("readBoundedRegularFile accepted a FIFO")
	}

	if err := os.Chmod(regular, 0o622); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if _, err := readBoundedRegularFile(regular); err == nil {
		t.Fatal("readBoundedRegularFile accepted a group/other-writable file")
	}
}
