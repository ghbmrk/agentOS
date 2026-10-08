# CRED-5t: Broker-held route failure triggers and fail-closed refresh test

Board section: Phase 0: harness and risk spikes.

Source: L3 point 3 (release) on #328. CRED-5's "a route that fails meanwhile" is undefined. Name the triggers: (a) a refresh or other response the egress proxy cannot match to a declared shape; (b) the provider refusing the login (account restriction).

- (a) must fail closed: an unswappable refresh response is dropped, never forwarded to the CLI (CRED-1). Add a qualification test with a synthetic canary token in an undeclared response shape.
- (b) the box stops retrying the plan route and tells the owner; repeated retries can worsen a restriction.

Spec wording for the triggers goes through an L1 spec-diff; the test and behavior are tier A (egress, vault).

**Requirements:** CRED-5, CRED-1, ADP-10

**Needs:** #328 merged
