# Vault: assumptions

Started with VAULT-REDACT (#1735) against SPEC CRED-7 and A14. Covers what `broker/vault`'s redactors rest on. Each row is a reading of the spec, with what changes if the reading is wrong.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| A1 | **Plan-login fields (VAULT-REDACT).** A `plan-login` entry (`KindPlanLogin`, written by `egress.PlanLogins`) is one JSON value holding a provider CLI's token set. `Redactor` and `HashRedactor` match its whole value and also every string inside it of `MinValueLen` (12) bytes or more, at any depth, each in the same encodings as any vault value, so a token echoed on its own is caught. Shorter strings (an account label) are not patterns: they are not credentials and could match innocent text. Other kinds are matched as whole values only. A value that is not valid JSON is matched whole. A JWT's three parts are not split: a lone part of an `id_token` echoed without its dots is not matched. | CRED-7, A14 | If another kind stores a structured value, add it to `redactValues`. If a provider's token is shorter than 12 bytes, lower the floor for that kind. |
