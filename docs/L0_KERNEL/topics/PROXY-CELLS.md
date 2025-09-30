# L0 Topic: Proxy Cells

Proxy cells let CEP show information that lives elsewhere without copying it into the kernel. Think of them as a skylight: you still see the sky through the cell, but the air stays outside so the house remains tidy.

Teams can wrap an existing datastore, a derived calculation, or a streaming window in a proxy. Enzymes and traversal code then follow the same tree they already know, while the proxy callbacks quietly fetch or refresh whatever the view needs.

## Technical Details
- A proxy cell is tagged with `CEP_TYPE_PROXY` and owns a lightweight `cepProxy` descriptor instead of a `cepData` payload or child store.
- The descriptor wires in a `cepProxyOps` table. Snapshot hooks provide inline bytes or external tickets for serialization, a restore hook rebuilds the view after replay, and an optional finalize hook tears down handles when the cell dies.
- `cep_proxy_initialize` seeds the cell and allocates the descriptor, while helpers like `cep_proxy_context`, `cep_proxy_snapshot`, and `cep_proxy_restore` expose the adapter from other subsystems.
- Serializers emit proxy snapshots as `CEP_CHUNK_CLASS_LIBRARY` chunks. Readers feed them back through `cep_proxy_restore`, which keeps replay deterministic and lets adapters decide how much to cache.
- Proxy cells keep the regular link/shadow plumbing, so links can safely reference a proxy and history tracking still flows through the parent store.

## Q&A
- **Do proxies replace normal cells?** No. Use a proxy when the payload lives outside CEP or is too large to clone. Normal cells remain the default for in-memory values and structured children.
- **What happens if a proxy cannot snapshot?** `cep_proxy_snapshot` returns `false`, and serialization fails fast. Adapters should always produce either inline bytes or an external ticket the replay side can resolve.
- **Can a proxy own children?** Not yet. Proxies are read-only façades today; expose structured views by materialising them into normal cells or by teaching the proxy to hand back a composite payload.
- **What if the importer lacks the adapter?** The deserializer stops as soon as a proxy manifest arrives without a matching proxy cell, keeping replays honest. Pre-seed the tree with the right proxy (or add a materialisation fallback) before ingesting archives.
