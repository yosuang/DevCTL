package kit

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"devctl/pkg/home"
)

// Track copies a file or directory into the kit configs and adds it to the manifest.
func (k *Kit) Track(targetPath string) error {
	slog.Debug("kit track: resolving path", "raw", targetPath)
	targetPath = os.ExpandEnv(targetPath)
	targetPath = home.Long(targetPath)

	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("resolving path: %w", err)
	}
	targetPath = absPath

	// Resolve symlinks
	resolved, err := filepath.EvalSymlinks(targetPath)
	if err != nil {
		return fmt.Errorf("resolving path: %w", err)
	}
	targetPath = resolved
	slog.Debug("kit track: resolved path", "path", targetPath)

	info, err := os.Stat(targetPath)
	if err != nil {
		return fmt.Errorf("reading target: %w", err)
	}

	m, err := k.loadOrInit()
	if err != nil {
		return err
	}

	// Check if already tracked (same target path)
	for _, cfg := range m.Configs {
		if home.Long(cfg.Target) == targetPath {
			return ErrAlreadyTracked
		}
	}

	// Determine key and source path
	basename := filepath.Base(targetPath)
	key := basename
	sourceName := basename

	// Check for basename collision and disambiguate
	if _, exists := m.Configs[key]; exists {
		parentDir := filepath.Base(filepath.Dir(targetPath))
		key = parentDir + "-" + basename
		sourceName = key
	}

	sourcePath := filepath.Join(configsDir, sourceName)
	fullSourcePath := filepath.Join(k.dir, sourcePath)

	// Create configs directory
	if err := os.MkdirAll(filepath.Join(k.dir, configsDir), dirPerm); err != nil {
		return fmt.Errorf("creating configs directory: %w", err)
	}

	// Copy file or directory
	if info.IsDir() {
		if err := copyDir(targetPath, fullSourcePath); err != nil {
			return fmt.Errorf("copying directory: %w", err)
		}
	} else {
		if err := copyFile(targetPath, fullSourcePath); err != nil {
			return fmt.Errorf("copying file: %w", err)
		}
	}

	// Add to manifest
	shortTarget := home.Short(targetPath)
	m.Configs[key] = ConfigEntry{
		Source: sourcePath,
		Target: shortTarget,
	}
	return k.Save(m)
}

// Untrack removes a config from the manifest. Does not delete the source file.
func (k *Kit) Untrack(name string) error {
	m, err := k.Load()
	if err != nil {
		return err
	}

	if _, ok := m.Configs[name]; !ok {
		return ErrNotTracked
	}
	delete(m.Configs, name)
	return k.Save(m)
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), dirPerm); err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, in)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	return err
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, _ := filepath.Rel(src, path)
		targetPath := filepath.Join(dst, rel)

		if d.IsDir() {
			return os.MkdirAll(targetPath, dirPerm)
		}
		return copyFile(path, targetPath)
	})
}
