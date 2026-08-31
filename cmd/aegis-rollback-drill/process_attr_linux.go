//go:build linux

package main

import "syscall"

// childProcessAttributes binds every child to a runner-owned process group and
// asks the kernel to kill the direct child if the rollback runner dies before
// its normal context-driven cleanup can execute.
func childProcessAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}
}
