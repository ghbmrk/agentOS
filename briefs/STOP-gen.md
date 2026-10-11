# STOP-gen: a RESUME in flight can undo a newer STOP across the local and text channels (CH-2)

Board section: Backlog refill (2026-10-11).

External finding 14 (Medium, tier A: `broker/owner`, `broker/localsrv`), approved by Mark on 2026-10-11. CH-2 says STOP always wins, but the STOP generation (`Channel.stops`) guarded only the text path:

- A local `/resume` on a sign-in older than 15 minutes runs `LocalSignIn` (code check) before `LocalResume`; `LocalResume` never checked the generation, so a texted STOP landing in that gap was undone.
- `LocalStop` never counted a STOP, so a texted RESUME that captured the generation earlier still passed `resumeUnlessStopped` and undid a local-page STOP.

Exposure: only with `agentosd -localui-uid` set (off by default) and a valid owner RESUME.

**Requirement:** one STOP generation for both channels. `LocalStop` counts under `stopMu`; `/resume` reads `StopGen` when the request arrives; `LocalResume` commits through `resumeUnlessStopped`.

**Tests:** a text STOP during a local RESUME's code check, and a local STOP during a texted RESUME's code check; each ends stopped.

**Needs:** —

**Gate:** lenses (security, tier A)

**State on the board:** in review
