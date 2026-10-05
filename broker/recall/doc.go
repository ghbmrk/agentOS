// Package recall is the broker-owned recall index (SPEC CAP-3).
//
// It holds everything the system has seen, each item with its provenance
// (source kind, account, ref, time, and the items it was derived from), and
// answers queries by full text (BM25), embeddings, and structured facts.
//
// Information flow (REV-5): every item carries a data label. Owner data
// (mail, files, calendar, owner chat, preferences) is always private, and
// task text is private unless the owner marked the task PUBLIC (D1); a
// derived item is at least as private as its parents. Search on behalf of an
// agent machine raises that machine to private before it returns any private
// result, and returns nothing if the raise fails. Render wraps results as
// untrusted content with their source, never as instructions.
//
// Owner corrections are explicit, editable preferences, written only with an
// authenticated owner-channel message as provenance. Ingested content can
// never create one.
//
// Custody (CRED-1): text, facts and refs are scrubbed of reusable
// authentication material before they are stored. Deletion propagates: it
// removes derived items, rewrites the store so no copy remains in the live
// file, and notifies OnDelete hooks (the event bus) to drop their copies.
//
// The package uses only the Go standard library and needs no inference
// (DEP-1); a local embedding service is optional. Assumptions are listed in
// ASSUMPTIONS.md next to this file.
package recall
