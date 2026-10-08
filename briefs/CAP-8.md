# CAP-8: Worker machines

Board section: Backlog refill (2026-10-05).

Worker machines (CAP-8; A14, A15): guest broker tools to create, exec in, read and write files of, `checkpoint`, `fork`, `diff`, `rollback` and destroy agent machines with no agent runtime, built from a base image. A worker inherits its creator's isolation, snapshot custody, budget reservation and data label (REV-5); a private writer raises a public worker to private (A14); RES-2 admission sizes how many run

**Needs:** P1-4, P1-7

**Gate:** lenses (security: executor path)

**State on the board before the 2026-10-08 index split:** merged (#146)
