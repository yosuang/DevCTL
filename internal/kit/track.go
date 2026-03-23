package kit

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"devctl/pkg/home"
)

// Track copies a file or directory into kit/<name>/ and adds it to the manifest.
// name is required and determines the subdirectory under kit/.
// mode specifies the deployment mode; if empty, defaults to DefaultConfigMode.
func (k *Kit) Track(targetPath, name, mode string) error {
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
		return fmt.Errorf("%w: %q", ErrInvalidConfigName, name)
	}

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

	configDir := k.ConfigDir(name)
	if err := os.RemoveAll(configDir); err != nil {
		return fmt.Errorf("cleaning config directory: %w", err)
	}
	if err := os.MkdirAll(configDir, dirPerm); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	var shortTargetDir string
	if info.IsDir() {
		// Directory: copy contents into kit/<name>/
		if err := copyDir(targetPath, configDir); err != nil {
			return fmt.Errorf("copying directory: %w", err)
		}
		shortTargetDir = filepath.ToSlash(home.Short(targetPath))
	} else {
		// Single file: copy into kit/<name>/<filename>
		if err := copyFile(targetPath, filepath.Join(configDir, filepath.Base(targetPath))); err != nil {
			return fmt.Errorf("copying file: %w", err)
		}
		shortTargetDir = filepath.ToSlash(home.Short(filepath.Dir(targetPath)))
	}

	// Add to manifest
	if mode == "" {
		mode = DefaultConfigMode
	}
	m.Configs[name] = ConfigEntry{
		TargetDir: shortTargetDir,
		Mode:      mode,
	}
	return k.Save(m)
}

// Untrack removes a config from the manifest. Does not delete the source files.
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
