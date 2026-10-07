# W5-D11 source receipt mutation fuzzing

FuzzReceiptAckPreservesSourceAssociations creates a fresh actual pipeline and
adapter for each input, using explicitly synthetic deterministic fixture entropy.
It persists an original notice/snapshot, then a later notice before attempting
Ack with mutated receipt bytes. The outer queue hash is recomputed legitimately,
so a refusal cannot depend only on detecting an unchanged outer hash.

Constructor or Ack rejection must leave the original generation consumable by its
authentic receipt. Acceptance of an equivalent encoding must consume exactly the
original generation. In both paths the later event must survive as generation
two, and repeated old acknowledgments cannot consume it. Inputs beyond the
admitted 128 KiB receipt bound are skipped; constructor rejection checks the
pending source remains unchanged. Seeds include authentic input, null/empty
records, extreme generations, trailing JSON and rehashed changed source text.

Run seeds with the package's normal tests/race checks. To mutate inputs locally:

```
go test ./digestqueue/changesource -run '^$' \
  -fuzz '^FuzzReceiptAckPreservesSourceAssociations$' -fuzztime=15s -parallel=2
```

Run from broker with a compatible Go toolchain. No model/provider/account calls
are made. This tests source-association preservation, not production entropy,
privileged producer isolation, a sender policy, queued/backup forget reach,
owner visibility or independent security acceptance. Review all source/transport
contracts before integration. Captured run/corpus evidence belongs to the review
export, not production state or a deployment qualification gate.
