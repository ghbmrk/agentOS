# Formal model of the key rules

`KeyVerdict.tla` models the key check (KEY-1 to KEY-7: chains, narrowing, stop, revocation, pause, expiry, labels, counted caps, and each key's hold windows). `HoldRule.tla` models the hold (KEY-8, KRN-4): when a step is held, for how long, and that nothing shortens it.

TLC checks every reachable state of both against their invariants: no link widens authority, holds never shorten, labels only accumulate, a narrowing or expiry admits nothing, revocation is final, and a held step never dispatches early. `vectors.py` then turns the states into test vectors, which `broker/kernel/key/formal_test.go` and `broker/kernel/formal_hold_test.go` replay through the real library and kernel. A rule change therefore has to change the model, the vectors and the code together, or CI fails.

Run (Java 11 or later, and tla2tools.jar v1.7.4, whose checksum `vectors.py` pins):

    curl -sSLo tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
    python3 broker/kernel/formal/vectors.py --jar tla2tools.jar            # model-check, rewrite the committed vectors
    python3 broker/kernel/formal/vectors.py --jar tla2tools.jar --check --full /tmp/formal
    (cd broker && FORMAL_VECTORS=/tmp/formal go test ./kernel/key ./kernel -run Formal)

Why TLA+ and what the model leaves out: `ASSUMPTIONS.md`.
