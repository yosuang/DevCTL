package formats

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type ManifestFile struct {
	Platform string          `json:"platform,omitempty"`
	Packages []PackageFormat `json:"packages"`
}

func (f *ManifestFile) Validate() error {
	if f.Platform == "" {
		return fmt.Errorf("missing platform")
	}

	if len(f.Packages) == 0 {
		return fmt.Errorf("no packages specified")
	}

	for i, pkg := range f.Packages {
		if err := pkg.Validate(); err != nil {
			return fmt.Errorf("package[%d]: %w", i, err)
		}
	}
	return nil
}

// IsCompatibleWithCurrentPlatform checks if the import file is compatible with the current platform.
// Returns true if Platform field matches runtime.GOOS
func (f *ManifestFile) IsCompatibleWithCurrentPlatform() bool {
	return f.Platform == runtime.GOOS
}

func LoadManifestFile(filePath string) (*ManifestFile, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var importFile ManifestFile
	if err := json.Unmarshal(data, &importFile); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	if err := importFile.Validate(); err != nil {
		return nil, fmt.Errorf("invalid format: %w", err)
	}

	if !importFile.IsCompatibleWithCurrentPlatform() {
		return nil, fmt.Errorf("import file is for platform '%s', but current platform is '%s'", importFile.Platform, runtime.GOOS)
	}

	return &importFile, nil
}

func SaveManifestFile(filePath string, f *ManifestFile) error {
	if f == nil {
		return fmt.Errorf("missing import file")
	}
	if err := f.Validate(); err != nil {
		return fmt.Errorf("invalid format: %w", err)
	}

	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
