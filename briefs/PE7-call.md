# PE7-call: PE7 condition 5, bound to the package that answers inbound calls

Board section: Integration: wiring merged packages into the box.

PE7 condition 5, bound to the package that answers inbound calls: while the agent sleeps (PE7), an inbound call gets SIP ringback plus the fixed clip "One moment, connecting you." and is connected after the wake. Test: a call during sleep hears ringback and the clip, then reaches the agent.

**Precondition:** PE7, inbound calls

**Owner:** 

**State on the board before the 2026-10-08 index split:** waits on the inbound-call package
