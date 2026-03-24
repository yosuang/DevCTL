package sync

import "errors"

var (
	ErrGitNotInstalled = errors.New("git is not installed")
	ErrRemoteRequired  = errors.New("remote URL is required for first sync")
	ErrConflict        = errors.New("merge conflict detected")
	ErrFetchFailed     = errors.New("failed to fetch remote status")
)
