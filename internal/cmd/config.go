package cmd

import (
	"devctl/internal/config"
	"devctl/pkg/cmdutil"
	"errors"
	"fmt"

	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
)

func NewCmdConfig(cfg *config.Config) *cobra.Command {
	var unset bool
	var list bool

	cmd := &cobra.Command{
		Use:   "config [<key> [<value>] | --unset <key> | --list]",
		Short: "Get and set configuration options",
		Long: heredoc.Doc(`
			Read, write, and remove entries in ~/.devctl/settings.json.

			  devctl config <key>              print the value
			  devctl config <key> <value>      set the value
			  devctl config --unset <key>      remove the key
			  devctl config --list             list all key=value pairs
		`),
		GroupID: "core",
		Args:    cobra.RangeArgs(0, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			store := config.NewStore(cfg.ConfigFile())

			if list {
				if unset || len(args) > 0 {
					return cmdutil.FlagErrorf("--list cannot be used with other arguments")
				}
				return runConfigList(cmd, store)
			}

			if unset {
				if len(args) != 1 {
					return cmdutil.FlagErrorf("--unset requires a key")
				}
				return runConfigUnset(store, args[0])
			}

			switch len(args) {
			case 0:
				return cmd.Help()
			case 1:
				return runConfigGet(cmd, store, args[0])
			case 2:
				return runConfigSet(store, args[0], args[1])
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&unset, "unset", false, "remove the given key")
	cmd.Flags().BoolVar(&list, "list", false, "list all key=value pairs")
	return cmd
}

func runConfigGet(cmd *cobra.Command, store *config.Store, key string) error {
	v, err := store.Get(key)
	if err != nil {
		if errors.Is(err, config.ErrKeyNotFound) {
			cmd.SilenceErrors = true
			return cmdutil.ErrSilent
		}
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), v)
	return nil
}

func runConfigSet(store *config.Store, key, value string) error {
	return store.Set(key, value)
}

func runConfigUnset(store *config.Store, key string) error {
	if err := store.Unset(key); err != nil {
		if errors.Is(err, config.ErrKeyNotFound) {
			return fmt.Errorf("key %q does not exist", key)
		}
		return err
	}
	return nil
}

func runConfigList(cmd *cobra.Command, store *config.Store) error {
	pairs, err := store.List()
	if err != nil {
		return err
	}
	w := cmd.OutOrStdout()
	for _, p := range pairs {
		fmt.Fprintf(w, "%s=%s\n", p.Key, p.Value)
	}
	return nil
}
