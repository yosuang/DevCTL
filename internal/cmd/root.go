package cmd

import (
	"devctl/internal/config"
	"devctl/internal/logging"
	"devctl/pkg/cmdutil"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var cfg = config.Init()

func NewCmdRoot() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:          "devctl",
		Short:        "Development CLI",
		Long:         `Development CLI`,
		SilenceUsage: true,
	}

	cfg.AddFlags(cmd.PersistentFlags())

	setupLogging(cfg)

	cmd.SetFlagErrorFunc(rootFlagErrorFunc)

	return cmd, nil
}

func rootFlagErrorFunc(_ *cobra.Command, err error) error {
	if errors.Is(err, pflag.ErrHelp) {
		return err
	}
	return cmdutil.FlagErrorWrap(err)
}

func setupLogging(cfg *config.Config) {
	logDir := filepath.Join(cfg.DataDir, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("Failed to create log dir: %v", err)
		os.Exit(1)
	}

	logfile := filepath.Join(logDir, fmt.Sprintf("%s.log", config.AppName))
	f, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}

	logger := logging.NewLogger(f, func() bool { return cfg.Debug })
	slog.SetDefault(logger)
}

type CommandError struct {
	error
	ExitCode int
}
