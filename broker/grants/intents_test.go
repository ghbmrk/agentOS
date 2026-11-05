package grants

import "github.com/ghbmrk/agentos/broker/journal"

// The intents and IDs below are built only by tests: the broker that
// submitted them has moved to the kernel (MIG-4), and the gate still
// parses them (ForgetGoal, ForgetAgentGoal, FollowOf).

// ForgetID is the ID of a forget intent for goal; nonce is unique per ask
// and holds no "/". The goal rides in the ID because the journal keeps
// identifiers as they are while it redacts params (journal.Redactor).
func ForgetID(nonce, goal string) string { return "forget/" + nonce + "/" + goal }

// ForgetAgentID is the ID of item 2 of the owner's forget request
// (W3-forget-b2b): taking back the agent's work since the task. It shares
// item 1's nonce.
func ForgetAgentID(nonce, goal string) string { return "forget-agent/" + nonce + "/" + goal }

// EvidenceIntent is the intent that sets the evidence destination to
// address on account, or clears it when address is empty (CH-20).
func EvidenceIntent(id, origin, address, account string) journal.Intent {
	if address == "" {
		account = ""
	}
	return journal.Intent{ID: id, Origin: origin, Account: journal.BrokerAccount, Action: journal.ActionEvidence,
		Params: map[string]any{ParamEvidenceAddress: address, ParamEvidenceAccount: account}, Executor: ExecutorName}
}

// FollowID is the ID of a follow intent: nonce is unique per ask and is 1
// to MaxFollowNonce lower-case hex characters; the digest comes before the
// name, which may hold anything the gate's name check allows. An empty
// name switches back to the project. Any other nonce (one holding "/"
// would shift the parse, OSS-10w L3) gives an ID FollowOf refuses, so the
// gate denies it as malformed.
func FollowID(nonce, digest, name string) string {
	if !followNonce(nonce) {
		nonce = ""
	}
	return "follow/" + nonce + "/" + digest + "/" + name
}

// FollowIntent is the local page's request to follow the root whose
// summary has digest, under the owner's name for it ("" to switch back to
// the project's own root).
func FollowIntent(nonce, name, digest string) journal.Intent {
	return journal.Intent{ID: FollowID(nonce, digest, name), Origin: originLocal, Account: journal.BrokerAccount,
		Action: journal.ActionUpdateFollow, Executor: FollowExecutor}
}
