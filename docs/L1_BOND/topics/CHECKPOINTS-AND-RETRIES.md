# L1 Topic: Checkpoints, Retries, and Recovery

## Introduction
Layer 1 reserves space for retry bookkeeping, but the current implementation keeps the footprint minimal. This topic documents what exists today and how you can extend it safely.

## Technical Details
### Current state
- `cep_init_l1` creates `/bonds/checkpoints` as a dictionary under the runtime workspace.
- No helper writes entries into that tree yet. Tests only assert the directory exists.
- `cep_tick_l1` walks the top-level children and deletes any that are empty, keeping the tree tidy if callers populate it.

### Extending checkpoints yourself
If you need retries today you can build on the existing folder:
1. Pick a schema (for example `/bonds/checkpoints/pending/<hash>` with child cells storing attempt counters or last-error text).
2. Write and read those cells from your own enzymes.
3. Continue calling `cep_tick_l1`; it removes empty families but leaves non-empty folders alone.

### Future directions (not implemented yet)
- Tie checkpoint entries to journal events so retries survive restarts without bespoke tooling.
- Track attempt counters and backoff policies alongside facet queue entries.
- Provide helpers that re-enqueue impulses based on the stored checkpoint metadata.

## Q&A
- **Will the current prune logic delete my data?** Only if you leave a folder empty. As long as your checkpoint entry keeps at least one child, `cep_tick_l1` leaves it in place.
- **Do retries run automatically?** No. You need to schedule your own replays (for example, by emitting new impulses) until a first-class retry loop lands.
- **Can I disable pruning?** Not directly, but you can store a sentinel child (e.g., `state=value`) to keep the folder non-empty even after you drain your own metadata.
- **How should I version my schema?** Nest another dictionary level (e.g., `/bonds/checkpoints/v1/...`) so future helpers can coexist without conflicting over field names.
