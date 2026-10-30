# Enforcer pairing seal: assumptions

Each row is a reading of the spec, or a property the code relies on, that a
reviewer may want to change (briefs/ENF.md slice r, #3692, decision 10).

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| ENF-r-1 | **The envelope is one hybrid KEM and one AEAD, as backup's.** An ephemeral X25519 key and an ML-KEM-768 encapsulation to the enforcer's pairing key; HKDF-SHA-256 over both shared secrets, with both ciphertexts, the recipient's keys and the device ID in its info (backup's X-Wing-style combiner); AES-256-GCM with the all-zero nonce, safe because each envelope has its own key; the device ID is also the AAD. So an envelope opens only with the enforcer's private half, only for the device it was sealed for, and any changed byte is refused. | STO-3, decision 10 (D-149's construction) | A third KEM or a standard combiner (X-Wing) replaces `seal`; the envelope's magic changes. |
| ENF-r-2 | **A sealed secret's device ID is printable ASCII** (`Device`): no space, quote or slash, 1 to 253 bytes. The page shows every core-chosen name quoted when it is not printable ASCII (ENF-b-1); requiring ASCII here means the line the owner signs names the device exactly as the policy does, with no escaping to match. | NET-4 Passkey rules | Allowing other names needs `Statement` to quote them as the page does, in both places. |
| ENF-r-3 | **The fingerprint is the envelope's SHA-256, not the secret's.** A hash of a short secret (a setup code) could be guessed offline by whoever reads the channel; the envelope's hash reveals nothing and is what the owner's diff already names. | decision 10 ("its reads report only a fingerprint") | — |
| ENF-r-4 | **The secret is at most 4096 bytes**, above a HomeKit long-term key pair, a Matter operational certificate chain or a keypad code, and the envelope fits a proposal link's fragment. | — | Raise `MaxSecret` with a measurement. |
| ENF-r-5 | **How the core learns the enforcer's pairing public key is not here.** `ParseRecipient` reads its 1216-byte encoding; pinning it at enrolment (slice c) and carrying it to the core (slice o's client) are those slices'. | decision 10 | — |
