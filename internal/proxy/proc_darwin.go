//go:build darwin

package proxy

import (
	"os/exec"
	"strconv"
	"strings"
)

func inspect(pid int) (bool, string) {
	if pid <= 1 {
		return false, ""
	}
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "state=", "-o", "command=").Output()
	if err != nil {
		return false, ""
	}
	text := strings.TrimSpace(string(out))
	if text == "" {
		return false, ""
	}
	state, command, _ := strings.Cut(text, " ")
	state = strings.TrimSpace(state)
	command = strings.TrimSpace(command)
	if state == "" || state[0] == 'Z' {
		return false, ""
	}
	return true, command
}
