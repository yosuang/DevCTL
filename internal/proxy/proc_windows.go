//go:build windows

package proxy

import (
	"context"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/windows"
)

func prepareChild(_ *exec.Cmd) {}

func inspect(pid int) (bool, string) {
	if pid <= 1 {
		return false, ""
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false, ""
	}
	defer windows.CloseHandle(handle)
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &n); err != nil {
		return true, ""
	}
	return true, windows.UTF16ToString(buf[:n])
}

func terminate(ctx context.Context, pid int) error {
	if pid <= 1 || pid == os.Getpid() {
		return errDidNotExit
	}
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		alive, _ := inspect(pid)
		if !alive {
			return nil
		}
		return err
	}
	defer windows.CloseHandle(handle)
	if err := windows.TerminateProcess(handle, 1); err != nil {
		return err
	}
	if waitUntilDead(ctx, pid, 2*time.Second) {
		return nil
	}
	return errDidNotExit
}
