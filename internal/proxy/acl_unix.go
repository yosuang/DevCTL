//go:build unix

package proxy

import "os"

func restrictDir(path string) error {
	if err := os.Chmod(path, 0o700); err != nil {
		return local("copy_incomplete", "file protection could not be applied")
	}
	return nil
}

func restrictFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return local("copy_incomplete", "file protection could not be applied")
	}
	return nil
}

func openForSync(path string) (*os.File, error) {
	return os.Open(path)
}

func syncFile(path string) error {
	f, err := openForSync(path)
	if err != nil {
		return local("copy_incomplete", "file protection could not be applied")
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return local("copy_incomplete", "file protection could not be applied")
	}
	return nil
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return local("copy_incomplete", "file protection could not be applied")
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return local("copy_incomplete", "file protection could not be applied")
	}
	return nil
}

func executableMode(mode os.FileMode) bool {
	return mode&0o111 != 0
}

func caseFoldPaths() bool {
	return false
}
