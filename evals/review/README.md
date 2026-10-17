# Reviewer eval corpus

Cases for `tools/revieweval.py` (REVIEW-eval, #2166), written by
`python3 tools/revieweval.py build --repo ghbmrk/agentOS` from merged PRs whose body carries a
`Defect: <ID>` line, plus known-clean PRs. Do not edit case files by hand: rebuild.

Score a reviewer command and keep a prompt change only if `compare` says `keep`:

    python3 tools/revieweval.py score --cmd "<reviewer>" --out new.json
    python3 tools/revieweval.py compare old.json new.json

`compare` exits 0 for keep, 1 for discard and 2 when the two scores ran on different case sets
(re-score both on the same cases). One case is one introducing PR; it holds the lines of every fix
to it, so a blocker for any of those defects is not a false blocker.
