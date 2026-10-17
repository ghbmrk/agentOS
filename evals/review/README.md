# Reviewer eval corpus

Cases for `tools/revieweval.py` (REVIEW-eval, #2166), written by
`python3 tools/revieweval.py build --repo ghbmrk/agentOS` from merged PRs whose body carries a
`Defect: <ID>` line, plus known-clean PRs. Do not edit case files by hand: rebuild.

Score a reviewer command and keep a prompt change only if `compare` says `keep`:

    python3 tools/revieweval.py score --cmd "<reviewer>" --out new.json
    python3 tools/revieweval.py compare old.json new.json
