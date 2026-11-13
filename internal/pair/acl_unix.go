//go:build unix

package pair

import "os"

func restrictDir(path string) error {
	if err := os.Chmod(path, 0o700); err != nil {
		return localCode("copy_incomplete", "file protection could not be applied")
	}
	return nil
}

func restrictFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return localCode("copy_incomplete", "file protection could not be applied")
	}
	return nil
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return localCode("copy_incomplete", "copy could not be saved")
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return localCode("copy_incomplete", "copy could not be saved")
	}
	return nil
}
