# The box's own mailbox: assumptions

Built for ADP-13 part 1 (the address choice) against SPEC ADP-13 "Name":
"The page offers four choices, each checked as available first: the box's
name (`dave.smith`), a random adjective and noun (`sleepy.llama`),
`email.assistant.<random digits>`, and one the owner types, checked live. A
shuffle control offers new ones. An address never contains a phone number.
A confirm screen shows the final address and states that it cannot be
renamed later." Package: `boxmail`. Each row is a reading a reviewer may
want to change.

| # | Assumption | Spec basis | Where |
|---|---|---|---|
| B1 | **Phone number**: any local part with seven or more digits, counted across dots, is refused, typed or generated, before any provider check. Seven is the shortest subscriber number in common use; generated addresses hold at most four (`email.assistant.0000`) or two (a taken name's suffix). | ADP-13 Name | `formErr` |
| B2 | **Checked first**: every generated choice is offered only after `Config.Available` said it is free; a taken one is replaced by another of its kind, at most `maxTries` (4) checks per kind, then that kind is left out. A failed check offers nothing, so nothing unchecked is shown as available. Shuffle is a new `Offer` call. | ADP-13 Name | `Offer` |
| B3 | **Box's name**: lowercased words joined by dots, hyphens and apostrophes dropped, common accented Latin letters folded (`Jose` with an acute accent to `jose`); a name with digits or another script gives no name choice rather than a mangled one. A taken name gets a two-digit suffix (`dave.smith.42`). | ADP-13 Name, CH-21 | `localFromName` |
| B4 | **Form**: 3 to 30 characters of `a-z`, `0-9` and single inner dots, the common subset of free providers' rules; the provider check (B2) has the final say. A typed name is trimmed and lowercased first. | ADP-13 Name | `Typed` |
| B5 | **Confirm wording** is in the box's first person (CH-21): "My address will be <address>. It cannot be renamed later; a new address would replace it." (a new address replaces the old one, ADP-13 Upkeep). | ADP-13 Name, CH-21 | `ConfirmText` |
| B6 | **Not here**: account creation by a credentialed executor (CRED-4b), recovery, the two-step seed, upkeep lines, the page itself (P2-2w). `Config.Available` is the executor's sign-up-form check once it exists. | ADP-13 | Later parts. |
