# PE7: Degraded mode: evaluate only while idle

Board section: Integration: wiring merged packages into the box.

Follow-up (R2 on #114): a degraded mode that evaluates only while the agent is idle or stopped, for a box where the agent and one replay machine do not fit together; with PE5

**Precondition:** PE2, PE5, PE5b

**Owner:** Next build item B

**State on the board before the 2026-10-08 index split:** parts 1 (vm, #147) and 2 (agentosd sleeper, #149) merged; part 3 (36 h resume, kept pairs, closest candidate first) in review; when W5a wires Loop 2, its `GuardConfig.ResumeFor` takes the same window (`learnPaths.ResumeFor`) (L3 on #153); design `/mnt/project-files/w3/pe7-design.md`
