package server

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"time"
)

func configurePythonProcessTree(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		// taskkill is the native Windows tree-termination utility. No shell is used.
		// Bound its runtime and retain direct termination if the utility is missing.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, "taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run(); err == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
	cmd.WaitDelay = 2 * time.Second
}

func cleanupPythonProcessTree(_ *exec.Cmd) {
	// Unix process-group cleanup is unavailable here. Do not taskkill by PID after
	// Wait: the parent PID could have been recycled. Native Windows tree-cancellation
	// requires taskkill to succeed while the parent is running and is not yet tested.
}
