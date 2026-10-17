# gvisor runtime: assumptions

What the no-network launch (A14, A14-r2) rests on. Each line is a fact about runsc this package does not test against a real runsc in unit CI; the integration job's `TestIntegrationGuestCannotDial` exercises the real binary.

- **Last value wins.** runsc parses global flags with Go's `flag` package, which keeps the last value given for a flag. `argv` relies on this: its pinned `--network=none` comes after every caller global flag, so a caller's `--network=host` is overridden.
- **No network flag past the subcommand.** `run` and `restore` define no `--network` flag of their own; runsc rejects one after the subcommand ("flag provided but not defined") and starts nothing. The tests also refuse any network flag after the subcommand, so this assumption is never the only guard.
- **No flag override.** Without `--allow-flag-override`, runsc ignores `dev.gvisor.flag.*` bundle annotations, so the bundle cannot reset `--network`. The tests fail on any argv naming that flag.
- **Caller global flags use `-name=value`.** `argv` treats the caller's leading `-`-prefixed args as global flags and the first other arg as the subcommand. A global flag given as `-name value` would put the pin between the flag and its value; runsc would then misparse the command and fail to start, never start with a network. Every caller in gvisor.go uses the `=` form (Exec's `--log=`, `--debug-log=`).
- **The integration job runs as root.** `TestStartAndRestorePassRunscNoNetwork` mounts the overlay and skips without root; `.github/workflows/ci.yml` runs `go test ./vm/...` as root in the integration job, so it runs there.

What the one-shot run (`RunOnce`, CH-23, ARC-5) rests on. The fake-runsc tests check the bundle and the call order; the root-only integration tests (`TestRunOnce*`) check each fact below against the real runsc.

- **V-photo-1. gVisor enforces RLIMIT_DATA.** The bundle's `process.rlimits` RLIMIT_DATA reaches the sentry's kernel, which refuses heap and anonymous mappings past it. RLIMIT_AS is not used: the Go runtime reserves address space far beyond what it touches and would fail at start. `TestRunOnceMemoryCap` checks it: 16 MiB under a 64 MiB cap runs, 256 MiB does not. If gVisor stops enforcing it, `OneShot.Cgroup` (a cgroup v2 memory limit) is the fallback.
- **V-photo-2. `runsc run` exits with the container's code.** `RunOnce` reads the program's exit code from runsc's; `TestRunOnceTimeoutKills` and the photo tests' refusal codes depend on it.
- **V-photo-3. The `--log` file stays empty unless runsc itself errs.** The program's stderr does not reach it. `RunOnce` takes any line there as runsc failing (`ErrOneShotFailed`), never as the program's exit.
- **V-photo-4. The sandbox's /dev is the sentry's own.** runsc mounts a virtual /dev over the root's empty one; no host device is reachable with only /proc in `mounts`.
