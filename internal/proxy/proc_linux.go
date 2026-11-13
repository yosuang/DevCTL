//go:build linux

package proxy

import (
	"os"
	"strconv"
	"strings"
)

func inspect(pid int) (bool, string) {
	if pid <= 1 {
		return false, ""
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false, ""
	}
	text := string(stat)
	end := strings.LastIndex(text, ")")
	if end < 0 || end+2 >= len(text) {
		return false, ""
	}
	if text[end+2] == 'Z' {
		return false, ""
	}
	image, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return true, ""
	}
	return true, image
}
