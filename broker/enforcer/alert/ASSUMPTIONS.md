# Enforcer texts, calls and light: assumptions

Each row is a reading of the spec, or a property the code relies on, that a
reviewer may want to change (briefs/ENF.md slice h, #3666).

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| ENF-h-a1 | **The closed list.** Texts: an unusual-time unlock or disarm, a recovery-code use, an enrolment, a paused channel (NET-2's list), a heater off or valve shut by a channel command (slice d's hook), and a log fork from the head copies (STO-1: the owner must choose). Calls: an alarm triggered, a door forced, repeated failed unlocks (SPEC marks which events call as a recommendation). Logged only: routine unlocks and locks. Which unlock is unusual is the lock rules' call (slice q). | NET-2 Texts and calls | One row in `kinds`. |
| ENF-h-a2 | **An alert stays open, and the light red, until the owner resolves it on the enforcer's page; a paused channel resolves only when the owner resumes it there.** Whether the kernel took the text (`Sent`) changes nothing but the record: the core may drop or falsely confirm it, and nothing on the channel resolves anything. | NET-2 Texts and calls, P6 | |
| ENF-h-a3 | **A repeat of an open alert's kind on the same device counts on it and sends nothing more.** A burst of failed unlocks costs one call, not one per attempt; the count and last time are on the page. | NET-2 ("only when the owner needs to act") | If the owner wants a second call after some time, add a re-notify interval per kind. |
| ENF-h-a4 | **Light colours: red for an open alert or a pending recovery; amber for the core down with nothing open; off otherwise.** SPEC fixes red; amber is a recommendation so "core down" shows on the light as the lifecycle matrix asks. The core counts as down until the daemon says it is up. `Refresh` re-shows the colour on a timer (slice l) for a bulb that was power-cycled. | NET-2 Texts and calls, brief lifecycle matrix | |
| ENF-h-a5 | **A text the kernel refused is offered again when the core comes back (`Core(true)`); one it took is not, since the enforcer cannot tell a delivery from a drop.** | NET-2 Texts and calls | |
| ENF-h-a6 | **The journal is append-only, one JSON line per record state, the latest per id winning; a torn last line is dropped.** | P6 | |
