package formats

import "devctl/internal/config"

func (p *PackageFormat) ToConfig() config.PackageConfig {
	return config.PackageConfig{
		Name:        p.Name,
		Version:     p.Version,
		InstalledBy: p.InstalledBy,
	}
}

func FromConfig(cfg config.PackageConfig) PackageFormat {
	return PackageFormat{
		Name:        cfg.Name,
		Version:     cfg.Version,
		InstalledBy: cfg.InstalledBy,
	}
}
