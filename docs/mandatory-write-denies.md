# Mandatory write denies

srt keeps a small set of paths **unwritable no matter what the write policy
says**. Even with `filesystem.allowWrite: ["/"]`, writes to these paths
fail inside the sandbox. This is a hardcoded security baseline, not a
config option: the lists live in `src/sandbox/sandbox-utils.ts`
(`DANGEROUS_FILES`, `DANGEROUS_DIRECTORIES`, `getDangerousDirectories()`)
and the per-platform builders — `linuxGetCwdMandatoryDenyPaths` /
`linuxGetMandatoryDenyPaths` in `linux-sandbox-utils.ts`,
`macGetMandatoryDenyEntries` in `macos-sandbox-utils.ts`.

Two distinct mechanisms make up the deny set:

- **Always-blocked names** — the static lists below, applied at the working
  directory and (within search depth) at every nested occurrence.
- **Git protections** — `.git/hooks` (always), `.git/config` (unless
  `filesystem.allowGitConfig: true`), and `.git/HEAD` (Linux nested repos
  only; see [`.git/HEAD`](#githead)).

The rest of this document covers the static lists and `.git`.

## Always-blocked files

`DANGEROUS_FILES` (`sandbox-utils.ts:17`), denied at their path in the
working directory and at every nested occurrence:

- `.gitconfig`, `.gitmodules`
- `.ripgreprc`

Fork (my branch): the shell RC files (`.bashrc`, `.bash_profile`,
`.zshrc`, `.zprofile`, `.profile`) and `.mcp.json` are not in this list.
They are ordinary files, so they follow the normal write policy and are
writable wherever `filesystem.allowWrite` covers them.

## Always-blocked directories

`getDangerousDirectories()` (`sandbox-utils.ts:35`) returns
`DANGEROUS_DIRECTORIES` minus `.git`, plus the Claude config subdirectories:

- `.vscode/`, `.idea/`
- `.claude/commands/`, `.claude/agents/`

**`.git` itself is not blocked.** `getDangerousDirectories()` filters it
out on purpose — git operations (updating refs, packing objects) need a
writable `.git`. Only the specific paths inside it are blocked, so a
`git commit` inside the sandbox still works.

## `.git` specifics

| Path | Denied | Configurable | Notes |
|---|---|---|---|
| `.git/hooks` | always | no | The sandbox-escape vector a planted hook would use |
| `.git/config` | by default | `filesystem.allowGitConfig: true` | Un-denying it lets `git remote set-url` and friends work; hooks stay blocked |
| `.git/HEAD` | Linux, nested repos only | no | See below |

**`.git/HEAD`** — On Linux, the nested-repo scan matches `**/.git/HEAD`
(HEAD is what marks a directory as a repository, so its hooks can be
denied before any hooks file exists), but the match is *redirected* to
`.git/hooks`: the emitted deny path replaces the `HEAD` component with
`hooks` (`linux-sandbox-utils.ts:502`). The result is an empty `.git/hooks`
stand-in for any nested repo whose `hooks/` directory does not exist yet.
Two consequences:

- A HEAD match for the **working directory's** own repository can never
  fire — the static deny already covers `.git/hooks` there.
- On **macOS** there is no HEAD handling at all. A nested repo's `hooks/`
  is covered by the anchored glob (Seatbelt pattern denies also match paths
  that do not exist yet, unlike Linux mounts), but `.git/HEAD` itself
  remains writable. The asymmetry is the HEAD file, not the hooks.

**Worktrees and fresh directories** — On Linux, the working directory's
`.git/hooks` and `.git/config` are denied *only when `.git` exists as a
directory* at wrap time (`linux-sandbox-utils.ts:296`). Two cases where
the protection is skipped, by design:

- In a **git worktree**, `.git` is a file (`gitdir: /path/to/main/.git/worktrees/...`).
  `.git/hooks` can never exist beneath a file, and a bwrap mount at it
  would fail the whole wrap.
- When **`.git` does not exist yet** (e.g. a fresh clone target), denying
  it would mount over the name and break `git init`.

macOS has no such check: its deny entries are emitted unconditionally, and
Seatbelt pattern denies cover nonexistent paths anyway. Nested occurrences
are unaffected on either platform — the scan (Linux) or the glob (macOS)
finds them by name wherever they lie.

## How it is enforced

**macOS** — Seatbelt deny entries (`macGetMandatoryDenyEntries`): a literal
path for the working directory copy of each name, plus an anchored glob
(`**/<name>/**` for directories, `**/<name>` for files) covering nested
occurrences at any depth.

**Linux** — bubblewrap can only deny a path by mounting over it, so there
is no glob. Two layers:

1. Static denials at the working directory (the lists above).
2. A **ripgrep scan** of the working directory for nested matches — one
   `rg --files --hidden --no-ignore --no-config` call with `--iglob`
   patterns for every dangerous name and `--max-depth
   <mandatoryDenySearchDepth + 1>`. Each match becomes a concrete deny.
   The scan skips `node_modules`, honors a 10-second kill (partial results
   are used; a scan that finds nothing at all is an error, never a
   silent pass), and denies unreadable directories wholesale.
   `mandatoryDenySearchDepth` (1–10, default 3) bounds how far the scan
   goes. ripgrep lists *files* at the file's depth, so the effective reach
   is: a dangerous *file* at or below the depth (`a/b/.gitconfig` at depth 2),
   and a dangerous *directory* — including a repository's `hooks/` and
   `config` — one level higher up, because what the scan lists is the file
   inside it.

A deny on a path that does not exist yet is enforced by creating a
placeholder mount point on the host (an empty read-only file, or a read-only
empty directory for a missing intermediate component), removed again when
the command exits. See README, "Write denies on paths that do not exist
yet (Linux)".

## Pinned ancestors (Linux)

Every existing ancestor of a protected path, up to the allowed write root
covering it, is made a mountpoint so it cannot be renamed or removed from
inside the sandbox: `mv`/`rmdir` of such a directory fails with `EBUSY`,
and `rm -rf` of a nested repository leaves the pinned directories and
protected files behind. See README, "Pinned directories (Linux)".

## Example

```
$ srt 'echo "bad" > .git/hooks/pre-commit'
/bin/bash: .git/hooks/pre-commit: Operation not permitted

$ srt 'echo "bad" > .gitconfig'
/bin/bash: .gitconfig: Operation not permitted
```

Both with `allowWrite: ["."]` in force. A shell RC file or `.mcp.json` in
the same writable directory is a normal file and writes to it succeed.
