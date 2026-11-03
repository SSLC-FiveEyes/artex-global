//go:build unix

package server

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Isolate the interpreter and its ordinary subprocesses from the ARTEX process
// group. Cancelling only the interpreter would leave native scanner children alive.
func configurePythonProcessTree(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return killPythonProcessTree(cmd) }
	// Bound inherited stdout/stderr pipes if an unexpected descendant holds them.
	cmd.WaitDelay = 2 * time.Second
}

func killPythonProcessTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

func cleanupPythonProcessTree(cmd *exec.Cmd) {
	// Also remove ordinary children if the Python parent exits before its child.
	_ = killPythonProcessTree(cmd)
}
