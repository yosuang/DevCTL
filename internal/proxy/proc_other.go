//go:build unix && !linux && !darwin

package proxy

import "syscall"

func inspect(pid int) (bool, string) {
	if pid <= 1 {
		return false, ""
	}
	err := syscall.Kill(pid, 0)
	if err != nil {
		return false, ""
	}
	return true, ""
}
