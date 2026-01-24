package executil

import (
	"os/exec"
	"runtime"
)

func LookPath(name string) string {
	path, err := exec.LookPath(name)
	if err == nil {
		return path
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("where", name)
	} else {
		cmd = exec.Command("which", name)
	}

	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	if len(output) > 0 {
		result := string(output)
		for i := 0; i < len(result); i++ {
			if result[i] == '\n' || result[i] == '\r' {
				return result[:i]
			}
		}
		return result
	}

	return ""
}

func IsInstalled(name string) bool {
	return LookPath(name) != ""
}
