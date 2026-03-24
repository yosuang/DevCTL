# Product Requirements Document: `devctl sync --status`

## 1. Executive Summary

Add a `--status` flag to the existing `devctl sync` command that displays a concise, actionable summary of the synchronization state between the local `~/.devctl/` configuration directory and its remote git repository. The feature enables users to quickly determine whether a sync operation is needed, what has changed locally, and whether the remote has new commits — eliminating guesswork and preventing stale configuration usage.

## 2. Problem Statement

Users of `devctl sync` currently have no way to check whether their local configuration is in sync with the remote repository without manually inspecting git state. This leads to:

- **Stale configurations** — users forget to sync after making local changes, causing inconsistency across machines.
- **Unnecessary syncs** — users run `devctl sync` "just in case" because they can't tell if it's needed.
- **Blind multi-machine usage** — when switching between machines, users have no quick way to verify if the current machine has the latest configuration.

**Target audience**: `devctl` users who manage their development environment configurations across multiple machines via git-based sync.

## 3. Goals & Success Metrics

| Goal | Metric |
|---|---|
| User can determine sync necessity in one command | Status output renders in a single terminal view (no scrolling) |
| Accurate local/remote comparison | Status reflects true git state after a fresh fetch |
| Clear actionability | Every status state maps to a clear next action (sync, init, or nothing) |

## 4. User Personas

**Primary — Multi-machine developer**: Uses devctl across 2+ machines (e.g., work desktop + laptop). Needs to quickly verify config consistency when switching machines.

**Secondary — Single-machine daily user**: Edits configs locally, needs a reminder when changes haven't been pushed to the remote backup.

## 5. Feature Specification

### P0 — MVP (this implementation)

| Feature | Description |
|---|---|
| `--status` flag | New boolean flag on `devctl sync` command. Mutually exclusive with `-m`. |
| Summary status line | One-line top-level status: `up to date`, `out of date`, `not initialized`, `conflict` |
| Last synced timestamp | Persisted in `.sync-state.json` (local-only, gitignored). Updated on each successful sync. Displayed as relative + absolute time. |
| Local changes detail | List of locally modified/added/deleted files with change type indicators. |
| Remote changes detail | Number of commits behind remote, detected via `git fetch` + log comparison. |
| Fetch on every invocation | `--status` always performs a `git fetch` to show up-to-date remote state. |
| Network failure handling | If fetch fails, exit with error and display a network unavailability hint. |
| Uninitialized state handling | When no remote is configured, display `not initialized` and guide user to run `devctl sync -r <url>`. |
| Flag conflict error | If `--status` is combined with `-m`, exit with error indicating flag conflict. |
| `.sync-state.json` storage | Stored in `~/.devctl/`, added to `.gitignore`. Records `last_synced_at` timestamp. |

### P1 — Future iterations

| Feature | Description |
|---|---|
| `conflict` detail | Show which files conflict when both local and remote have diverged. |
| Vault sync status | Indicate whether vault secrets have unsynchronized changes. |
| `--status` in CI/scripting | Machine-readable output format (e.g., `--status --json`). |

### P2 — Long-term

| Feature | Description |
|---|---|
| Auto-sync reminder | Optional hook/notification when status is `out of date` for extended time. |
| `devctl status` global | Unified status view combining sync + kit + vault state. |

## 6. User Flows

### Flow 1 — Daily status check (happy path)

```
$ devctl sync --status

Sync status: out of date
  Last synced: 2 hours ago (2026-03-24 14:30)
  Local:
    modified  kit/zsh/zshrc
    added     kit/git/gitconfig
  Remote: 1 new commit (behind)
```

User sees changes exist → runs `devctl sync`.

### Flow 2 — Everything in sync

```
$ devctl sync --status

Sync status: up to date
  Last synced: 10 minutes ago (2026-03-24 16:20)
```

No local/remote sections displayed when there are no changes.

### Flow 3 — Not initialized

```
$ devctl sync --status

Sync status: not initialized
  Run 'devctl sync -r <remote-url>' to set up sync.
```

### Flow 4 — Network failure

```
$ devctl sync --status

Error: failed to fetch remote status: network unavailable.
  Check your internet connection and try again.
```

### Flow 5 — Flag conflict

```
$ devctl sync --status -m "save"

Error: --status cannot be used with -m.
```

### Flow 6 — Conflict state (local and remote both changed)

```
$ devctl sync --status

Sync status: conflict
  Last synced: 1 day ago (2026-03-23 09:00)
  Local:
    modified  kit/zsh/zshrc
  Remote: 2 new commits (behind)
```

User sees both sides have changes → runs `devctl sync` knowing a merge will occur.

## 7. Non-Functional Requirements

- **Performance**: Status check (excluding network fetch) should complete in < 200ms. Fetch adds network latency but should timeout within 10 seconds.
- **No side effects**: `--status` must NEVER modify sync state, commit, or push. Read-only operation (except the `git fetch`).
- **Backward compatibility**: Adding `--status` does not change the existing `devctl sync` behavior when the flag is not provided.

## 8. Constraints & Assumptions

- **Constraint**: Requires git to be installed (same as existing sync).
- **Constraint**: Requires network access for accurate remote status (no offline fallback by design).
- **Assumption**: `.sync-state.json` will be written atomically to avoid corruption.
- **Assumption**: The first `--status` invocation before any sync has occurred will show "Last synced: never".

## 9. Open Questions

_None — all decisions have been resolved through discussion._

## 10. Roadmap

| Phase | Scope |
|---|---|
| **MVP** | `--status` flag, summary line, last synced time (`.sync-state.json`), local/remote change detection, fetch-on-check, error handling (network, uninitialized, flag conflict) |
| **V1** | Conflict file detail, vault status, JSON output mode |
| **V2** | Auto-reminder hooks, unified `devctl status` command |
