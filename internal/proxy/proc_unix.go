//go:build unix

package proxy

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func prepareChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminate(ctx context.Context, pid int) error {
	if pid <= 1 || pid == os.Getpid() {
		return errDidNotExit
	}
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	if waitUntilDead(ctx, pid, 2*time.Second) {
		return nil
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	if waitUntilDead(ctx, pid, 2*time.Second) {
		return nil
	}
	return errDidNotExit
}
