//go:build darwin

package main

import "syscall"

// childProcessAttributes keeps Darwin compilation available for developer
// inspection. The drill itself rejects non-Linux execution before mutation.
func childProcessAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
