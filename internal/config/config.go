package config

const (
	AppName        = "devctl"
	defaultDataDir = ".devctl"
)

// Config holds the configuration for devctl.
type Config struct {
	Debug     bool
	DataDir   string
	ConfigDir string
}
