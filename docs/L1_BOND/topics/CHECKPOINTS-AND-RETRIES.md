# L1 Topic: Checkpoints, Retries, and Recovery

## Introduction
When work pauses mid-beat, checkpoints make sure the bond layer resumes exactly where it left off. They keep retries orderly so you never duplicate relationships or lose track of failed facets.

## Technical Details
### Checkpoint anatomy
- Checkpoints live under `/bonds/checkpoints/<heartbeat-id>/<impulse-id>`.
- Each record stores the impulse path, the current op count, and any staged context for resuming work.
- The kernel's append-only semantics guarantee the checkpoint history stays intact even if the runtime restarts mid-write.

### Retry flow
- When an enzyme fails, it writes diagnostic metadata onto the checkpoint entry and yields. The heartbeat leaves the entry pending while other work continues.
- On the next beat, `cep_tick_l1` revisits pending checkpoints. If prerequisites look healthy, the impulse is reissued to the original handler or kept in place for another pass depending on the stored policy.
- Successful retries append an acknowledgement node; once the folder is empty, `cep_tick_l1` removes the shell so stale directories do not accumulate.

### Cleanup strategy
- `cep_tick_l1` prunes empty checkpoint folders each beat, keeping the tree tidy while leaving the most recent history intact for audits.
- Long-lived failures bubble into `/bonds/checkpoints/stalled` with rich metadata, making them easy to inspect through tooling.
- Operators can force-complete a checkpoint by writing a resolution tag; the heartbeat will skip the retry and record the override in history.

## Q&A
- **Will retries reorder impulses?** No. Checkpoint management respects heartbeat sequencing; retries run in the same order they were staged.
- **What if a handler is gone after a restart?** Provide a fallback plugin or flag the checkpoint as unresolved. The heartbeat keeps the entry visible until a resolution arrives.
- **How can I monitor retry health?** Stream checkpoint counters into telemetry cells or export them through your observability stack for dashboards.
- **Do checkpoints impact performance?** Entries are small and stored in the kernel. Pruning keeps the footprint bounded even on busy systems.
