//go:build darwin || linux

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadBoundedConfigFileRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aegis.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := readBoundedConfigFile(path)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("readBoundedConfigFile accepted FIFO input")
		}
	case <-time.After(time.Second):
		t.Fatal("readBoundedConfigFile blocked while opening FIFO input")
	}
}

func TestReadBoundedConfigFileRejectsFinalSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(dir, "aegis.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := readBoundedConfigFile(link); err == nil {
		t.Fatal("readBoundedConfigFile accepted final symlink")
	}
}
