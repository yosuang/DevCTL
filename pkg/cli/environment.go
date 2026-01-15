package cli

import (
	"os"
	"strconv"

	"github.com/spf13/pflag"
)

// EnvSettings describes all the environment settings.
type EnvSettings struct {
	Debug bool
}

func New() *EnvSettings {
	env := &EnvSettings{}
	env.Debug, _ = strconv.ParseBool(os.Getenv("devctl_DEBUG"))

	return env
}

// AddFlags binds flags to the given flagset.
func (s *EnvSettings) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&s.Debug, "debug", s.Debug, "enable verbose output")
}
