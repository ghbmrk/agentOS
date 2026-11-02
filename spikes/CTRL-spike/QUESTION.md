# CTRL-spike: the ordered mini PC against two text claims

Brief: briefs/CTRL-spike.md. Unit: GMKtec NucBox M6 Ultra ordered 2026-10-11 (synthetic addresses and canaries only).

| # | Question | Text it backs | Pass rule |
|---|---|---|---|
| 1 | Does the box boot a flashed stick with no key press? | HW-13, HW-6 recipes | `key_presses == 0` and the stick's boot marker is seen |
| 2 | Does USB4 networking carry port 2 traffic at line rate for 60 s? (row CTRL-usb4, after G1: A17, D-104) | HW-12 | duration >= 60 s, throughput >= 2350 Mbit/s (94% of a 2.5GbE port 2), zero retransmit stalls |

The Wi-Fi access-point spike is retired: the core never turns Wi-Fi on (D-178).

A failure is a result: it names the text that needs rework (HW-6, HW-12). SPEC.md is not edited here; a needed change goes on the PR's Findings line.

Time box: one sitting with the unit. Run `probe.py` on the box, then `check.py` on each JSON it writes.

Run order and recorded measurements:

1. `probe.py boot --model M6U --key-presses N` on the stick's first boot (N counted by the operator).
2. Under CTRL-usb4 only: `probe.py usb4 --server <peer>` with `iperf3 -s` on the peer over the USB4 link.
3. `check.py results/*.json` prints PASS/FAIL per spike; paste into RESULT.md.
