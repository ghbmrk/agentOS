# HOST-1f: Give the TPM's dictionary-attack settings back as they were

Board section: Backlog refill (2026-10-05).

Give the TPM's dictionary-attack settings back as they were (HW-8, D7; Security S1 on #183): `tpmseal.TakeLockout` reads the original `TPM_PT_MAX_AUTH_FAIL`, `TPM_PT_LOCKOUT_INTERVAL` and `TPM_PT_LOCKOUT_RECOVERY` before setting its own, keeps them in the vault, and `ReleaseLockout` restores them; the owner's guide tpm-lockout line then says both are given back

**Needs:** P2-4b (tpmseal, boot PIN #42)

**Gate:** lenses (Security, strongest tier)

**State on the board before the 2026-10-08 index split:** in review
