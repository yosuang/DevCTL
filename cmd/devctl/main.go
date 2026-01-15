package main

import (
	devctlcmd "devctl/internal/cmd"
	"errors"
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
		var cerr *devctlcmd.CommandError
		if errors.As(err, &cerr) {
			os.Exit(cerr.ExitCode)
		}
		os.Exit(1)
	}
}
