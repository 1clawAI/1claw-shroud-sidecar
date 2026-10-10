# Platform packages

One npm package per supported target, each containing nothing but the
`shroud-sidecar` binary for that platform:

| package | os | cpu |
| --- | --- | --- |
| `@1claw/shroud-sidecar-linux-x64` | linux | x64 |
| `@1claw/shroud-sidecar-darwin-arm64` | darwin | arm64 |

`@1claw/hermes` lists both under `optionalDependencies`. npm installs only the
one matching the host — that is what the `os` and `cpu` fields are for — and
skips the other without failing. This is the pattern esbuild, swc and sharp
use.

## Why these exist

Hermes used to install the sidecar by fetching `install.sh` from the `main`
branch and piping it to `sh`. The script itself was reasonable (release
artifacts, sha256 verification, version pinning), but the arrangement had
three problems:

1. The checksum step was **fail-open** — a missing `checksums.txt` printed a
   warning and installed anyway, so an integrity check could be skipped by
   withholding a file.
2. Hermes fetched the script from `main` rather than a tag, so the least
   pinned form of a script built to be pinned.
3. `latest_tag()` resolved the version at install time, so two installs a week
   apart produced different binaries.

A package manager already solves all three. The version is fixed by Hermes'
dependency range and the lockfile, npm verifies the tarball against the
integrity hash recorded there, and nothing has to run a shell or reach GitHub
at install time. CI and offline installs work.

The binaries are not committed. `bin/shroud-sidecar` is empty in git; the
release workflow drops the built binary in and publishes, so a package version
can only ever contain a binary built from that tag.
