//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSealedExecutableBindsExecutionAndExposesNoSiblingFD(t *testing.T) {
	t.Setenv("HOST_CANARY", "must-not-enter-sealed-process")
	root := t.TempDir()
	candidatePath := filepath.Join(root, "candidate")
	rollbackPath := filepath.Join(root, "rollback")
	candidateScript := []byte("#!/bin/sh\n" +
		"if [ -n \"${HOST_CANARY:-}\" ]; then printf inherited-host-secret; exit 92; fi\n" +
		"for descriptor in /proc/self/fd/*; do\n" +
		"  target=$(readlink \"$descriptor\" 2>/dev/null || true)\n" +
		"  case \"$target\" in *rollback-sibling*) printf sibling-visible; exit 91;; esac\n" +
		"done\n" +
		"printf original-candidate\n")
	rollbackScript := []byte("#!/bin/sh\nprintf rollback-sibling\n")
	if err := os.WriteFile(candidatePath, candidateScript, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rollbackPath, rollbackScript, 0o700); err != nil {
		t.Fatal(err)
	}

	candidate, candidateDigest, err := snapshotExecutable(candidatePath, "candidate")
	if err != nil {
		t.Fatalf("snapshot candidate: %v", err)
	}
	defer func() { _ = candidate.close() }()
	rollback, _, err := snapshotExecutable(rollbackPath, "rollback-sibling")
	if err != nil {
		t.Fatalf("snapshot rollback: %v", err)
	}
	defer func() { _ = rollback.close() }()

	if err := verifyExecutableSeals(candidate.file); err != nil {
		t.Fatalf("candidate seal set: %v", err)
	}
	if _, err := candidate.file.WriteAt([]byte("X"), 0); err == nil {
		t.Fatal("sealed candidate allowed content replacement")
	}
	if err := candidate.file.Truncate(candidate.size + 1); err == nil {
		t.Fatal("sealed candidate allowed growth")
	}
	if err := candidate.file.Truncate(candidate.size - 1); err == nil {
		t.Fatal("sealed candidate allowed shrink")
	}
	replaceExecutable(t, candidatePath, []byte("#!/bin/sh\nprintf replacement-candidate\n"))
	replaceExecutable(t, rollbackPath, []byte("#!/bin/sh\nprintf replacement-rollback\n"))

	stdout, stderr, err := runBoundedProcess(context.Background(), 3*time.Second, candidate, identityEnvironment())
	if err != nil {
		t.Fatalf("execute sealed candidate: stderr=%q err=%v", stderr, err)
	}
	if stdout != "original-candidate" {
		t.Fatalf("sealed execution output = %q, want original-candidate", stdout)
	}
	if strings.Contains(stdout+stderr, "sibling-visible") {
		t.Fatalf("candidate observed sibling executable fd: stdout=%q stderr=%q", stdout, stderr)
	}
	finalDigest, err := candidate.digest()
	if err != nil {
		t.Fatalf("final candidate digest: %v", err)
	}
	if finalDigest != candidateDigest || candidateDigest != fmt.Sprintf("%x", sha256Sum(candidateScript)) {
		t.Fatalf("sealed digest drift: initial=%s final=%s", candidateDigest, finalDigest)
	}
}

func TestChildProcessAttributesBindGroupAndParentDeathSignal(t *testing.T) {
	attributes := childProcessAttributes()
	if attributes == nil || !attributes.Setpgid || attributes.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("child process attributes = %+v, want Setpgid and SIGKILL Pdeathsig", attributes)
	}
}

func TestSealedExecutableRejectsSourceFIFOWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "candidate-fifo")
	if err := syscallMkfifo(fifo, 0o700); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := snapshotExecutable(fifo, "candidate-fifo")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("snapshotExecutable accepted FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("snapshotExecutable blocked on FIFO")
	}
}

func replaceExecutable(t *testing.T, destination string, data []byte) {
	t.Helper()
	temporary := destination + ".replacement"
	if err := os.WriteFile(temporary, data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, destination); err != nil {
		t.Fatal(err)
	}
}

func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func syscallMkfifo(path string, mode uint32) error {
	if err := syscall.Mkfifo(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}
