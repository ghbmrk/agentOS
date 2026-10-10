# W3-builder-ship: Ship the builder so owners never see the repeats-only line

Board section: Integration: wiring merged packages into the box.

UX-134-1: so owners never see the learning-from-repeats-only line. **agentosd side (this package):** `-builder-image` defaults to `builder` and `-builder-launch` to `/usr/lib/agentos/builder/launch.json`, fail-closed (default image not registered: no builder, the repeats-only line; registered without its launch file: the not-running line). **Remaining, for P2-1 (#41 or its follow-up):** the box image builds `guest/builder/build-rootfs.sh` into /usr, installs `guest/builder/launch.json` at that path (root-owned, 0644), its agentosd unit passes `-image builder=<dir>`, and its agentos-egress unit passes `-builder-from <agent machine>`

**Precondition:** W3-builder-image, P2-1

**Owner:** this package (P3-2)

**State on the board before the 2026-10-08 index split:** agentosd side in progress; P2-1 side queued
