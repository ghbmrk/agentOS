// Package recall is the broker-owned recall index (SPEC CAP-3).
//
// It holds everything the system has seen, each item with its provenance
// (source kind, account, ref, time, and the items it was derived from), and
// answers queries by full text (BM25), embeddings, and structured facts.
//
// Information flow (REV-5): every item carries a data label. Only web,
// timer, task (D1: marked PUBLIC) and broker-labelled agent items can be
// public; every other kind is private whatever the caller declares. A
// derived item is at least as private as its parents (private if a parent is
// unknown), and a label never falls on re-ingest. Search on behalf of an
// agent machine either reads public items with public-only statistics, or
// raises the machine to private before it runs; it returns nothing if the
// raise fails. Render wraps results as untrusted content with their source,
// never as instructions, and without scores.
//
// Owner corrections are explicit, editable preferences, written only with an
// authenticated owner-channel message as provenance. Ingested content can
// never create one.
//
// Custody (CRED-1): text, facts and refs are scrubbed of reusable
// authentication material before they are stored. Identity is a keyed hash
// of the raw source name, so scrubbing never merges or loses items.
// Deletion propagates: it removes derived items, keeps a durable tombstone
// (so stale content is refused and late hooks are replayed), rewrites the
// store so no copy remains in the live file, and notifies OnDelete hooks
// (the event bus) even for sources not yet indexed.
//
// The package uses only the Go standard library and needs no inference
// (DEP-1); a local embedding service is optional. Assumptions are listed in
// ASSUMPTIONS.md next to this file.
package recall
