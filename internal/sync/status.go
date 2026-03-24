// status.go implements the read-only sync status check.
package sync

import (
	"fmt"
	"strings"
	"time"
)

// StatusState represents the overall sync state.
type StatusState string

const (
	StatusUpToDate       StatusState = "up to date"
	StatusOutOfDate      StatusState = "out of date"
	StatusNotInitialized StatusState = "not initialized"
	StatusConflict       StatusState = "conflict"
)

// ChangeType represents the kind of local file modification.
type ChangeType string

const (
	ChangeModified ChangeType = "modified"
	ChangeAdded    ChangeType = "added"
	ChangeDeleted  ChangeType = "deleted"
)

// FileChange represents a single local file modification.
type FileChange struct {
	Type ChangeType
	Path string
}

// StatusResult holds the complete sync status.
type StatusResult struct {
	State        StatusState
	LastSyncedAt *time.Time
	LocalChanges []FileChange
	RemoteBehind int
}

// Status performs a read-only check of the sync state.
// It always fetches from the remote to ensure accuracy.
func (r *Repo) Status() (*StatusResult, error) {
	if err := r.checkGit(); err != nil {
		return nil, err
	}

	if !r.IsInitialized() {
		return &StatusResult{State: StatusNotInitialized}, nil
	}

	if err := r.fetch(); err != nil {
		return nil, ErrFetchFailed
	}

	state, err := r.readState()
	if err != nil {
		return nil, fmt.Errorf("read sync state: %w", err)
	}

	result := &StatusResult{}
	if state != nil {
		result.LastSyncedAt = &state.LastSyncedAt
	}

	result.LocalChanges, err = r.localChanges()
	if err != nil {
		return nil, fmt.Errorf("detect local changes: %w", err)
	}

	result.RemoteBehind, err = r.remoteBehind()
	if err != nil {
		return nil, fmt.Errorf("detect remote changes: %w", err)
	}

	hasLocal := len(result.LocalChanges) > 0
	hasRemote := result.RemoteBehind > 0

	switch {
	case hasLocal && hasRemote:
		result.State = StatusConflict
	case hasLocal || hasRemote:
		result.State = StatusOutOfDate
	default:
		result.State = StatusUpToDate
	}

	return result, nil
}

// fetch runs git fetch origin, returning an error only on real failures (not empty remotes).
func (r *Repo) fetch() error {
	_, err := r.run("fetch", "origin")
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "couldn't find remote ref") {
		return nil
	}
	return err
}

// localChanges detects uncommitted file changes visible to git (respects .gitignore whitelist).
func (r *Repo) localChanges() ([]FileChange, error) {
	out, err := r.run("status", "--porcelain")
	if err != nil {
		return nil, err
	}

	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return nil, nil
	}

	var changes []FileChange
	for line := range strings.SplitSeq(trimmed, "\n") {
		if len(line) < 4 {
			continue
		}
		xy := line[:2]
		path := strings.TrimSpace(line[3:])

		change := FileChange{Path: path}
		switch {
		case strings.Contains(xy, "D"):
			change.Type = ChangeDeleted
		case xy == "??" || strings.Contains(xy, "A"):
			change.Type = ChangeAdded
		default:
			change.Type = ChangeModified
		}
		changes = append(changes, change)
	}

	return changes, nil
}

// remoteBehind returns the number of commits the local branch is behind origin/main.
func (r *Repo) remoteBehind() (int, error) {
	if _, err := r.run("rev-parse", "--verify", "origin/main"); err != nil {
		return 0, nil
	}

	if _, err := r.run("rev-parse", "--verify", "HEAD"); err != nil {
		// No local commits but remote has some — count all remote commits.
		out, countErr := r.run("rev-list", "origin/main", "--count")
		if countErr != nil {
			return 0, countErr
		}
		var count int
		fmt.Sscanf(strings.TrimSpace(out), "%d", &count)
		return count, nil
	}

	out, err := r.run("rev-list", "HEAD..origin/main", "--count")
	if err != nil {
		return 0, err
	}

	var count int
	fmt.Sscanf(strings.TrimSpace(out), "%d", &count)
	return count, nil
}
