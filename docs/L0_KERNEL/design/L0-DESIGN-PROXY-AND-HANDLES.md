# L0 Design: Proxies, Handles, and External Resources

## Nontechnical Summary
Some data lives outside the kernel—files on disk, sockets, GPU buffers. Proxy cells let Layer 0 represent those resources without copying them in. Instead, adapters hold references and expose deterministic snapshots so serialization, replay, and traversal still work. The design keeps foreign resources under control: everything is reference-counted, errors surface through the same logs, and adapters decide how to retain or release handles on demand.

## Decision Record
- Proxy payloads are opaque handles or streams tagged with library-defined operations; they never expose process-local pointers directly.
- Retain/release hooks let adapters manage lifetimes so repeated access does not leak native resources.
- Serialization requires adapters to implement snapshot/restore logic; handles that cannot be replayed must refuse serialization explicitly.
- Proxies appear as regular cells, keeping traversal, locking, and history mechanics consistent.
- Stream adapters segment IO through effect logs, allowing heartbeat-aware retries and deterministic hashing.

## Subsystem Map
- Code
  - `src/l0_kernel/cep_cell_stream.c` — proxy helper APIs, snapshot/restore plumbing.
  - `src/l0_kernel/stream/cep_stream_stdio.c`, `cep_stream_zip.c`, `cep_stream_effects.c` — standard adapters and effect logging.
  - `src/l0_kernel/cep_cell.c` — integration points where proxies appear in cell lifecycles.
- Tests
  - `src/test/l0_kernel/test_stream.c`, `test_streams_randomized.c`, `test_stream_zip.c` — adapter behaviour, replay, error handling.
  - `src/test/l0_kernel/test_serialization.c` — proxy snapshots during serialization.
  - `src/test/l0_kernel/test_ops.c` (indirect) — effect logs when proxies emit operational evidence.

## Operational Guidance
- Always document adapter preconditions (e.g., file must exist, descriptor must be seekable) and enforce them when retain is called.
- When adding new adapters, provide deterministic snapshot bytes; include version tags so deserialisers can reject incompatible snapshots.
- Monitor adapter-specific metrics—handle counts, open streams, retry rates—to catch leaks before they affect the kernel.
- Decide early whether adapters support historical playback; if not, mark cells as non-serializable and provide alternate audit paths.
- Keep adapter code minimal and side-effect free outside of their defined retain/release/read/write/snapshot routines.

## Change Playbook
1. Refresh understanding via this design doc and `docs/L0_KERNEL/topics/PROXY-CELLS.md`, `docs/L0_KERNEL/topics/IO-STREAMS-AND-FOREIGN-RESOURCES.md`.
2. Introduce new adapter files under `src/l0_kernel/stream/` or extend `cep_cell_stream.c` with care; ensure reference counting and error propagation remain deterministic.
3. Add focused tests (`test_stream*.c`, serialization suites) covering acquisition, snapshotting, and replay.
4. Update any integration docs or pack guides referencing the adapter.
5. Run `meson test -C build --suite stream` and `meson compile -C build docs_html`; finish with `python tools/check_docs_structure.py`.
6. If new effects or metrics are introduced, extend `docs/L0_KERNEL/L0-TUNING-NOTES.md` accordingly.

## Global Q&A
- **What if an adapter cannot be serialized?** It should refuse snapshot requests and surface a deterministic error; upstream callers must provide alternate persistence strategies.
- **How are resource leaks prevented?** Retain/release hooks and heartbeat-driven cleanup ensure handles close when cells disappear or adapters finalise.
- **Can proxies expose mutable views?** They should surface deterministic windows; mutating external state must either go through adapters with idempotent semantics or be wrapped in transactions.
- **How do errors propagate?** Adapters return standard error codes; the kernel records them via effect logs so upper layers can react or retry.
- **Do proxies participate in history?** Yes. Their cells carry timestamps like any other; snapshots capture state transitions even if the heavy data stays outside the kernel.
