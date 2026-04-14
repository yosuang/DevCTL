# Spec: `devctl config`

## 1. Summary

Add a `devctl config` command for managing persistent configuration in `~/.devctl/settings.json`.

## 3. Command Shape

| Command | Behavior |
|---|---|
| `devctl config <key>` | Print the value to stdout. Exit 1 if the key does not exist. |
| `devctl config <key> <value>` | Set the key to value. Create the file if missing. |
| `devctl config --unset <key>` | Delete the key. Exit 1 if the key does not exist. |
| `devctl config --list` | Print all `key=value` pairs, one per line, sorted. |

Keys are flat dotted strings. `settings.json` stores them as a flat JSON object:

```json
{
  "sync.remote.url": "git@github.com:user/dotfiles.git"
}
```

## 4. Known Keys

| Key | Purpose |
|---|---|
| `sync.remote.url` | Remote git URL used by `devctl sync`. |

The list grows as future commands add config.

## 5. Impact on `devctl sync`

Remove the `--remote/-r` flag. On every run, `devctl sync` reads `sync.remote.url`. When the key is unset and no git remote is configured yet, sync exits with a hint pointing at the new command.

## 6. User Flows

### Flow 1 — First sync

```
$ devctl sync
Error: remote URL not configured
  Run: devctl config sync.remote.url <URL>

$ devctl config sync.remote.url git@github.com:user/dotfiles.git

$ devctl sync
Synced successfully
```

### Flow 2 — Read a value

```
$ devctl config sync.remote.url
git@github.com:user/dotfiles.git
```

### Flow 3 — Update a value

```
$ devctl config sync.remote.url git@github.com:user/new-remote.git

$ devctl config sync.remote.url
git@github.com:user/new-remote.git
```

Updating the key does not reconfigure the git remote on an already-initialized repo. Users who want to repoint an existing repo must update the git remote themselves. Covering that case is out of scope for this spec.

### Flow 4 — Remove a value

```
$ devctl config --unset sync.remote.url

$ devctl config sync.remote.url
$ echo $?
1
```

### Flow 5 — List everything

```
$ devctl config --list
sync.remote.url=git@github.com:user/dotfiles.git
```

### Flow 6 — Get a missing key

```
$ devctl config nonexistent.key
$ echo $?
1
```

No output, exit code 1. Matches `git config` behavior.

### Flow 7 — Unset a missing key

```
$ devctl config --unset nonexistent.key
Error: key 'nonexistent.key' does not exist
```

### Flow 8 — Invalid invocations

```
$ devctl config
# prints help, same as `devctl config -h`

$ devctl config --unset
Error: --unset requires a key

$ devctl config --list --unset sync.remote.url
Error: --list cannot be used with --unset
```

## 7. Out of Scope

- Automatic migration of existing git remote URLs into `sync.remote.url`.
- Typed values. Every value is a string.
- Per-command config files, global vs. local scoping, `--edit` to open an editor.
