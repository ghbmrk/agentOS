# localsrv: assumptions

Started for ONB-private-save-fail l2 (#1623) against ONB-3 and CAP-9. Each row is a reading a later change could overturn.

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| LS1 | The vault's provider list answers `EnrollClosed` only once setup's seal is written (egress K17), and only setup's own finish seals, after it found no listed provider owed an answer. So a sealed vault took no answer since the check, and finish's owed check and `privateOK` treat `EnrollClosed` as listing nothing: the answer is not owed, and finish can record after a seal whose finished record failed to save. Every other list failure, `EnrollNotOpen` included, still owes. | ONB-3, CAP-9 | If anything else can seal the vault, or a sealed vault can take answers, an owed answer could be dropped with the vault keeping an older yes; finish must then owe on `EnrollClosed` again. |
| LS2 | **Setup's device-code op relays and keeps nothing (#1264 c4e2b; ONB-3, CRED-5).** `OpSetupDeviceCode` answers only for a provider the vault lists as signing in by device code and that `SignIn.Ready` says can start now; it returns the https page, the code and the issuer name, each shape-checked, and logs none of them. A provider whose last sign-in still waits answers `ErrSignInBusy`, so the page says to wait rather than that it failed. Rate: 4 starts a minute, 90 s each. | ONB-3, CRED-5 | A provider that signs in by redirect, not code, needs another op. |
