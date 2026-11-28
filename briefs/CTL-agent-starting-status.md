# CTL-agent-starting-status: STATUS during boot shows a starting line

Work item: #6176 (release items 2 and 3 of the UX lens on #6136, comment 6981648344; row CTL-owner-text-lost, #5429). Tier A. Written 2026-11-28 against main at b97a19d0.

## Goal

1. **(CH-12, OWN-17 recovery)** Between `daemon.Run` and the guest plane opening, `lateStatus` has no keeper, so STATUS reads `agentNotSet` ("I need an update or a restart"). The owner-text reply (#6136) points at STATUS, so an owner who texts during boot is told to restart a start that is only in progress. Fix: STATUS says "Your agent is starting." until every start-up path of the machine plane has run (a keeper stored, or a cause named through `off`/`caps`), and `agentNotSet` only after that with no keeper and no cause.
2. **(CH-12)** The keeper starts at `agentWaiting` ("waiting for memory") before its first `ensure`. Fix: it starts at the neutral starting line and moves on only when its first try returns.

## Scope

- `broker/cmd/agentosd/{main.go,agent.go,zz_agentstarting_test.go,capoff_test.go,ASSUMPTIONS.md}` (`capoff_test.go`: `capBox` boots a `newLateStatus` and its one-agent-line guard refuses the starting line too; review release items on #6753)
- `briefs/CTL-agent-starting-status.md`

**Requirement IDs:** CH-12, OWN-17.

## Acceptance tests

- `broker/cmd/agentosd/zz_agentstarting_test.go::TestAgentStatusDuringBootSaysStarting`: before the plane opens, and with a keeper stored that has not tried yet, STATUS is the starting line, not `agentNotSet` or `agentWaiting`; after a try refused for memory it is `agentWaiting`.
- `::TestAgentStatusAfterBootWithNoKeeperSaysNotSet`: after start-up with no keeper and no cause, `agentNotSet`.
- `::TestAgentStatusOffWinsOverStarting`: a cause named before the daemon runs wins over the starting line.
- `::TestAgentStatusCapsCauseWinsOverStarting`: a cause named through caps during boot keeps STATUS to that one agent line.
- `::TestMainSettlesAfterEveryAgentStartPath`: `main` calls `settle` exactly once, after every keeper store and `caps.agentOff`.
