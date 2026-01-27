package formats

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
)

type ImportFile struct {
	Platform string          `json:"platform,omitempty"`
	Packages []PackageFormat `json:"packages"`
}

func (f *ImportFile) Validate() error {
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
func (f *ImportFile) IsCompatibleWithCurrentPlatform() bool {
	return f.Platform == runtime.GOOS
}

func LoadImportFile(filePath string) (*ImportFile, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var importFile ImportFile
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
