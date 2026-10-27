# MIG-4-recovery-len: the card's recovery key opens the store's recovery slot (#3406)

Work item: #3406. Tier A. Serves REC-1, REC-4, BAK-1.

## The gap

The Owner Card prints a 160-bit recovery key (`broker/card/recoverykey.go`, 40 symbols, eight checked groups). The sealed store's recovery slot (`seal.RecoveryLen`), `agentos-enroll -recovery-file` and `backup.RecipientFor` take 32 bytes. Nothing maps one to the other, so no printed card opens the slot or the backups.

## Decision: the card keeps 40 symbols; the store key is derived from them

`card.StoreRecoveryKey(text)` parses the typed or printed key (same normalisation and group checks as the card), and returns HKDF-SHA256(160-bit key, no salt, info `agentos.card.store-recovery.v1`, 32 bytes). Enrollment and a REC-4 rotation seal the slot and the backup recipient to that value; recovery derives it again from what the owner types.

The issue recommended the other way (print the store's 32 bytes as 52 symbols). Derivation is chosen because:

1. Every card already printed keeps working; a 52-symbol card would orphan them.
2. The slot and the backups stay at 32 bytes, so nothing sealed in CI images changes shape (the issue's reason for not shrinking the slot holds here too).
3. The old core still parses the card's key as 160 bits (`recovery.ParseRecoveryKey`, `agentos-egress` custody). That code is frozen and out of this lane; a 52-symbol card would break it until it is deleted.
4. The owner types 40 symbols, not 52, when restoring.

The cost: the slot and the backups are at the card's 160 bits, not 256. 160 bits is beyond offline search, and above AES-128's key size against a quantum search, so it meets the backups' ML-KEM-768 hybrid at NIST category 1 or better [Inference].

## Scope

`broker/card/recoverykey.go`, `broker/card/storekey_test.go`, this brief. `card.go`, `card_test.go` and `ASSUMPTIONS.md` are held by #3402 (D-111); the card's ASSUMPTIONS row C1 gains one sentence pointing here once #3402 merges.

**Acceptance tests:** `broker/card/storekey_test.go`: `TestCardRecoveryKeyOpensStoreSlot` (a generated card's key, retyped in lower case with spaces, opens a store created from it and derives the same backup recipient; another card's key is `ErrWrongFactor`), `TestStoreRecoveryKeyVector` (the derivation pinned to a vector computed outside Go), `TestStoreRecoveryKeyRefuses` (mistyped, short, long, foreign and 64-hex inputs refused).

## Not here

Calling `StoreRecoveryKey` from the code that writes `/run/agentos-setup/recovery` and from the REC-4 rotation page belongs to MIG-4-recovery-r4a and r4b, which this unblocks.
