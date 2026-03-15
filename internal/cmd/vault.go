package cmd

import (
	"bufio"
	"devctl/internal/vault"
	"devctl/pkg/cmdutil"
	"devctl/pkg/home"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"devctl/internal/config"

	"github.com/spf13/cobra"
)

func NewCmdVault(cfg *config.Config) *cobra.Command {
	vaultDir := filepath.Join(cfg.ConfigDir, "vault")

	cmd := &cobra.Command{
		Use:     "vault <command>",
		Short:   "Manage encrypted secrets",
		GroupID: "core",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newCmdVaultInit(vaultDir))
	cmd.AddCommand(newCmdVaultSet(vaultDir))
	cmd.AddCommand(newCmdVaultGet(vaultDir))
	cmd.AddCommand(newCmdVaultDelete(vaultDir))
	cmd.AddCommand(newCmdVaultList(vaultDir))

	return cmd
}

func newCmdVaultInit(vaultDir string) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize the vault",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			v := vault.New(vaultDir)
			if err := v.Init(); err != nil {
				return vaultError(err)
			}
			fmt.Fprintf(os.Stderr, "Vault initialized at %s\n", home.Short(vaultDir))
			return nil
		},
	}
}

func newCmdVaultSet(vaultDir string) *cobra.Command {
	return &cobra.Command{
		Use:   "set <KEY> [VALUE]",
		Short: "Set a secret",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			key := args[0]
			var value string

			if len(args) == 2 {
				value = args[1]
			} else if cmdutil.IsTerminal(os.Stdin) {
				fmt.Fprintf(os.Stderr, "Enter value for %s: ", key)
				line, err := bufio.NewReader(os.Stdin).ReadString('\n')
				if err != nil && err != io.EOF {
					return fmt.Errorf("reading stdin: %w", err)
				}
				value = strings.TrimRight(line, "\r\n")
			} else {
				data, err := io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("reading stdin: %w", err)
				}
				value = strings.TrimRight(string(data), "\r\n")
			}

			v := vault.New(vaultDir)
			if err := v.Set(key, value); err != nil {
				return vaultError(err)
			}
			return nil
		},
	}
}

func newCmdVaultGet(vaultDir string) *cobra.Command {
	return &cobra.Command{
		Use:   "get <KEY>",
		Short: "Get a secret",
		Args:  cmdutil.ExactArgs(1, "KEY is required"),
		RunE: func(cmd *cobra.Command, args []string) error {
			v := vault.New(vaultDir)
			val, err := v.Get(cmd.Context(), args[0])
			if err != nil {
				return vaultError(err)
			}
			fmt.Fprint(os.Stdout, val)
			return nil
		},
	}
}

func newCmdVaultDelete(vaultDir string) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <KEY>",
		Short: "Delete a secret",
		Args:  cmdutil.ExactArgs(1, "KEY is required"),
		RunE: func(_ *cobra.Command, args []string) error {
			v := vault.New(vaultDir)
			if err := v.Delete(args[0]); err != nil {
				return vaultError(err)
			}
			return nil
		},
	}
}

func newCmdVaultList(vaultDir string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all secret keys",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			v := vault.New(vaultDir)
			keys, err := v.List()
			if err != nil {
				return vaultError(err)
			}
			for _, k := range keys {
				fmt.Println(k)
			}
			return nil
		},
	}
}

func vaultError(err error) error {
	switch {
	case errors.Is(err, vault.ErrNotInitialized):
		return fmt.Errorf("vault not initialized\nRun: devctl vault init")
	case errors.Is(err, vault.ErrAlreadyInitialized):
		return fmt.Errorf("vault already initialized at %s", home.Short(""))
	case errors.Is(err, vault.ErrKeyNotFound):
		return fmt.Errorf("%w\nRun: devctl vault list    (to see available keys)", err)
	case errors.Is(err, vault.ErrInvalidKeyName):
		return fmt.Errorf("invalid key — must be UPPER_SNAKE_CASE (e.g., MY_TOKEN)")
	default:
		return err
	}
}
