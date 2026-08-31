//go:build darwin

package main

import "testing"

func TestChildProcessAttributesKeepDarwinProcessGroupIsolation(t *testing.T) {
	attributes := childProcessAttributes()
	if attributes == nil || !attributes.Setpgid {
		t.Fatalf("Darwin child process attributes = %+v, want Setpgid", attributes)
	}
}
