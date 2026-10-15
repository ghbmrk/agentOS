# localsrv: assumptions

Started for ONB-private-save-fail l2 (#1623) against ONB-3 and CAP-9. Each row is a reading a later change could overturn.

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| LS1 | The vault's provider list answers `EnrollClosed` only once setup's seal is written (egress K17), and only setup's own finish seals, after it found no listed provider owed an answer. So a sealed vault took no answer since the check, and finish's owed check and `privateOK` treat `EnrollClosed` as listing nothing: the answer is not owed, and finish can record after a seal whose finished record failed to save. Every other list failure, `EnrollNotOpen` included, still owes. | ONB-3, CAP-9 | If anything else can seal the vault, or a sealed vault can take answers, an owed answer could be dropped with the vault keeping an older yes; finish must then owe on `EnrollClosed` again. |
