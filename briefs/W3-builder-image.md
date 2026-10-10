# W3-builder-image: The minimal builder image for W3-builder

Board section: Integration: wiring merged packages into the box.

The minimal builder image for W3-builder (C-3c-3): `guest/builder/build-rootfs.sh` builds a root file system holding only `agentos-builder`, a static brief client whose toolchain is the skill format's validator (no shell, no runtime, no agent tools, nothing downloaded). It reads `/brief`, calls the model route, posts `/candidate`, sends refusals back to the model for up to 4 rounds, and otherwise ends the job on `/done`. Registered with `-image builder=<dir>`, named by `-builder-image builder`, launched by `guest/builder/launch.json`. CI runs a job under gVisor

**Precondition:** W3-builder

**Owner:** loops thread (P3-2)

**State on the board before the 2026-10-08 index split:** in review
