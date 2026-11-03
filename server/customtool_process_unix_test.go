//go:build unix

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Only local Python sleep processes are created. No network or scanner binaries.
func TestExecPythonCancellationKillsDescendants(t *testing.T) {
	interp := detectPython()
	if interp == "" {
		t.Skip("python unavailable")
	}
	for _, mode := range []string{"timeout", "cancel", "parent-exits"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			pidPath := filepath.Join(dir, "child.pid")
			code := `import json, os, subprocess, sys, time
p = json.load(sys.stdin)
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
with open(p['pid_path'], 'w') as f:
    f.write(str(child.pid))
print('offline child started', flush=True)
if p['mode'] != 'parent-exits':
    time.sleep(60)
`
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			timeout := 10 * time.Second
			if mode == "timeout" {
				timeout = 2 * time.Second
			}
			type result struct {
				output string
				err    error
			}
			done := make(chan result, 1)
			go func() {
				out, err := execPython(ctx, interp, "tree", code, map[string]any{"pid_path": pidPath, "mode": mode}, dir, nil, timeout)
				done <- result{out, err}
			}()
			deadline := time.Now().Add(5 * time.Second)
			var child int
			for time.Now().Before(deadline) {
				data, _ := os.ReadFile(pidPath)
				child, _ = strconv.Atoi(string(data))
				if child > 0 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if child <= 0 {
				cancel()
				t.Fatal("child process did not become ready")
			}
			cleanupChild := true
			defer func() {
				if cleanupChild {
					_ = syscall.Kill(child, syscall.SIGKILL)
				}
			}()
			if mode == "cancel" {
				cancel()
			}
			select {
			case got := <-done:
				if mode == "timeout" && !errors.Is(got.err, context.DeadlineExceeded) {
					t.Fatalf("timeout not propagated: %v %s", got.err, got.output)
				}
				if mode == "cancel" && got.err == nil {
					t.Fatal("cancelled execution reported success")
				}
			case <-time.After(6 * time.Second):
				cancel()
				t.Fatal("child-held output pipes blocked cancellation")
			}
			deadline = time.Now().Add(2 * time.Second)
			for processStillRunning(child) && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if processStillRunning(child) {
				t.Fatal("Python cancellation/exit left a live descendant")
			}
			cleanupChild = false
		})
	}
}

func processStillRunning(pid int) bool {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return false
	}
	// Container PID 1 may not reap adopted zombies. A zombie is already terminated
	// and cannot send requests, even though kill(pid, 0) still sees its process entry.
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		if end := strings.LastIndex(string(data), ") "); end >= 0 {
			state := string(data)[end+2:]
			if strings.HasPrefix(state, "Z ") || strings.HasPrefix(state, "X ") {
				return false
			}
		}
	}
	return true
}
