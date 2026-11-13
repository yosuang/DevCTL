package main

import (
	devctlcmd "devctl/internal/cmd"
	"log/slog"
	"os"
)

func main() {

	cmd, err := devctlcmd.NewCmdRoot()

	if err != nil {
		slog.Warn("command failed", slog.Any("error", err))
		os.Exit(1)
	}

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
