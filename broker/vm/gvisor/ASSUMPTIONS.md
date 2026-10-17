# gvisor runtime: assumptions

What the no-network launch (A14, A14-r2) rests on. Each line is a fact about runsc this package does not test against a real runsc in unit CI; the integration job's `TestIntegrationGuestCannotDial` exercises the real binary.

- **Last value wins.** runsc parses global flags with Go's `flag` package, which keeps the last value given for a flag. `argv` relies on this: its pinned `--network=none` comes after every caller global flag, so a caller's `--network=host` is overridden.
- **No network flag past the subcommand.** `run` and `restore` define no `--network` flag of their own; runsc rejects one after the subcommand ("flag provided but not defined") and starts nothing. The tests also refuse any network flag after the subcommand, so this assumption is never the only guard.
- **No flag override.** Without `--allow-flag-override`, runsc ignores `dev.gvisor.flag.*` bundle annotations, so the bundle cannot reset `--network`. The tests fail on any argv naming that flag.
- **Caller global flags use `-name=value`.** `argv` treats the caller's leading `-`-prefixed args as global flags and the first other arg as the subcommand. A global flag given as `-name value` would put the pin between the flag and its value; runsc would then misparse the command and fail to start, never start with a network. Every caller in gvisor.go uses the `=` form (Exec's `--log=`, `--debug-log=`).
- **The integration job runs as root.** `TestStartAndRestorePassRunscNoNetwork` mounts the overlay and skips without root; `.github/workflows/ci.yml` runs `go test ./vm/...` as root in the integration job, so it runs there.
