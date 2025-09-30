# L1 Topic: Being Cards and Identity Hygiene

## Introduction
Being cards are Layer 1's identity badges. They help the runtime remember who a record belongs to, track friendly labels, and keep external IDs glued to their canonical counterpart. This topic explains how they fit together and how to keep them clean over time.

## Technical Details
### What a being owns
- **Canonical tag.** Each being lives under `/data/CEP/L1/beings/<tag>/<key>`, where `<tag>` marks the class (person, system, asset) and `<key>` is a deterministic hash of the caller's identifier.
- **Role dictionary.** The being cell keeps `id/`, `labels/`, and `meta/` sub-dictionaries that carry external identifiers, user-friendly names, and arbitrary metadata copies.
- **History trail.** Edits append children with fresh timestamps; old values remain reachable for audits via heartbeat queries.

### Claiming and updating beings
- **Claim flow.** `cep_being_claim` accepts a `cepBeingSpec` with desired tags, identifiers, and metadata. It looks for an existing match and only creates a new cell if nothing matches.
- **Merging hints.** When duplicate records surface, mark the losing being with a `meta/merge_target` tag and call the dedicated merge helper to retarget bonds and contexts.
- **External references.** Keep stable handles by storing upstream IDs in `id/external` slots; enzymes can resolve them later without recomputing hashes.

### Guarding data quality
- **Policy hooks.** Guard rails check for required fields (for example, labels or classification) before a claim is accepted.
- **Audit fields.** Record provenance such as `meta/source_system` or `meta/import_batch` so later investigations can trace edits.
- **Expiry.** Soft-delete outdated beings using the kernel's lifetime flags; Layer 1 retains history, and adjacency pruning will clean up mirrors once no bonds refer to the record.

## Q&A
- **Can two beings share the same external ID?** Not once the policy hooks are in place. Duplicate claims will return the existing record and log a warning via the telemetry enzyme.
- **How do I store personally identifiable information safely?** Keep raw PII in encrypted external stores and store only references or pseudonyms in the being metadata.
- **What happens when a being is deleted?** The kernel marks it with a `deleted` timestamp. Layer 1 enzymes treat it as retired and prune dependent bonds during heartbeat maintenance.
- **Do I need migrations for new metadata fields?** No. Append the values into `meta/` with new tags; history already keeps previous revisions intact.
