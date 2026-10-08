# Notification runtime reconciliation assumptions

| # | Assumption | Spec basis | If it changes |
| --- | --- | --- | --- |
| NR1 | Native merge-tree consumes complete exact commit objects and emits an isolated object, not a source/main ref mutation. Runtime diagnostics use that exact tree. | OP-1, CH-15 | Refuse missing objects, partial patch substitution and pin mismatches; refresh through a separate explicit evidence packet. |
| NR2 | Clean text or passing synthetic runtime tests cannot establish semantic/security/release acceptance. | CH-11, CH-15 | Keep independent external review and W5-D47-Q/W5-D50-Q/W5-D51-Q qualifications. |
| NR3 | The old proposal ancestry is immutable; current-main operating/lane/claim/pilot adoption is separate. | OP-1 | Do not silently rebase/push any published head or write main. |
| NR4 | Git native objects/configuration and UTF-8 metadata are trusted local inputs; repository replacement refs must never substitute pinned objects. External custom merge drivers are unsupported. | OP-1 | Ignore replacement objects, refuse custom drivers or unsupported framing/encoding; preserve original failure, do not infer compatibility. |
| NR5 | Inventories describe all tracked recursive Git tree entries including symlink/gitlink identities; they do not attest submodule contents, untracked data, filesystem custody or external dependency/media state. | CH-15, OP-1 | Qualify those independently; do not interpret inventory equality as deployment or security proof. |
