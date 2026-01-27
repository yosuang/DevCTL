package formats

import (
	"encoding/json"
	"fmt"
	"os"
)

type ImportFile struct {
	Packages []PackageFormat `json:"packages"`
}

func (f *ImportFile) Validate() error {
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

	return &importFile, nil
}
