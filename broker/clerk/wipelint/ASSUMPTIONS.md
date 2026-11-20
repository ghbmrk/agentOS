# Sealer key-wipe lint: assumptions

Built for LINT-sealer-key-wipe-fu (#6349). Each row is a reading a reviewer may want to change.

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| LINT-sealer-key-wipe-fu-1 | A sealer is anything whose method set, as a type or through its pointer, satisfies `clerk.Sealer` (`types.Implements`); a constructor is found by its result type alone, so a package need not import clerk to be held. | CLK-1, STO-2 | A sealer of another shape (a second interface, a func pair) gets its own interface in the rule. |
| LINT-sealer-key-wipe-fu-2 | Only linux binaries ship, so a file that only another platform compiles holds no key on a box; the files lintload.Unread reports (another tag set, cgo, non-Go) are listed one by one in `unreadOK` with why each holds no sealer. | HW-8, REV-CHK-lintload-2 | A second shipped platform adds a load for it. |
| LINT-sealer-key-wipe-fu-3 | A byte slice is wiped by `clear(v)` and a byte array by `clear(v[:])`; a string cannot be wiped, and a key behind a pointer, in a struct or map, or of a type the lint cannot read (any, a type set without terms) cannot be wiped by one statement at the call, so a listed key of those forms fails. | STO-2 | A key form that a statement can wipe gets its own form and wipe shape. |
| LINT-sealer-key-wipe-fu-4 | `vendor/` and nested modules are other modules: their declarations are not read, so a use in broker of one of their functions that makes a sealer from a possible key fails unlisted. | CLK-1 | Vendored code that must itself wipe a key is held where broker calls it. |
