# W3-forget: Owner-facing forget command

Board section: Integration: wiring merged packages into the box.

Owner-facing forget command (CAP-3): the owner's authenticated forget of a task calls `learning.forgetTask` (W3-tasks part 2, change C23). Conditions: before anything is deleted, the owner is told which learned skills the forget affects (potency on #160); it retries until every save succeeds and says nothing is forgotten before then; the reply goes out only after the save and states the cascade as a count only ("Forgotten. I also undid 2 things I learned from it."); if a save fails it says the task was not forgotten and to try again (UX on #160); its reach also covers backups made before the forget and machine snapshots (security C2 on #160)

**Precondition:** W3-tasks part 2, W5

**Owner:** Next build item B

**State on the board before the 2026-10-08 index split:** split: W3-forget-a, W3-forget-b (design /mnt/project-files/w3/w3-forget-design.md)
