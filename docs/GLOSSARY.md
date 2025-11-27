# CEP Glossary

This glossary collects common acronyms and phrases used across the docs so newcomers can decode the jargon quickly.

## Acronyms (alphabetical)
- **AEAD (Authenticated Encryption with Associated Data):** Chacha20/XChacha20 modes used by the serializer and secmeta payloads.
- **AES/GCM (Advanced Encryption Standard, Galois/Counter Mode):** Authenticated encryption mode; CEP’s serializer rejects AES-GCM and uses Chacha/XChacha instead.
- **API (Application Programming Interface):** Public function/struct surface.
- **ASAN (AddressSanitizer):** Compiler sanitizer used in dedicated `build-asan` runs to catch memory bugs.
- **ASYNC (Async I/O fabric):** Reactor/channels/completion-queue layer handling non-blocking I/O.
- **CAS (Content-Addressable Storage):** Hash-addressed blob store for large payloads; referenced by hash from cells.
- **CEH (Common Error Health):** CEI health mirror under `/net/peers/<peer>/ceh/**`.
- **CEI (Common Error Interface):** Structured error/diagnostic facts emitted into mailboxes with severity/topic metadata.
- **CEP (Cascade Evolutionary Processing):** The project/runtime name; default domain for tags.
- **CFLT:** Frame wrapper used when the flat serializer compresses an entire frame (deflate).
- **CPCL (Cache/Persistence Controller Layer):** Informal nickname for branch controllers that decide when/how to flush to CPS.
- **CPS (Content Persistence Service):** Layer 0 persistence engine that writes branch frames to disk using the flat serializer.
- **CQ (Completion Queue):** Async I/O queue drained once per beat (Capture→Compute) to surface finished async requests.
- **CRC (Cyclic Redundancy Check):** Checksum (CRC32C) used in frames and payload chunks.
- **DAG (Directed Acyclic Graph):** Shape of pipeline graphs (stages and edges).
- **DT (Domain/Tag ID):** Packed identifier (`cepDT`) used throughout the kernel.
- **E3 (Episodic Enzyme Engine):** Layer 0 executor for long-running work sliced across beats (`op/ep` dossiers); also the shorthand used in tables.
- **FED (Federation):** Transport/organ subsystem moving flat frames across peers.
- **FFI (Foreign Function Interface):** CEP adapters use this pattern to wrap external libraries/resources as proxies.
- **IOCP (I/O Completion Ports):** Windows async backend; CEP’s reactor can target IOCP on that platform.
- **IPC (Inter-Process Communication):** Pipes/sockets used by some transport providers; CEP treats them as byte movers.
- **KV (Key-Value):** Shorthand for key-value stores.
- **MPL (Mozilla Public License):** Repo license.
- **OID (Object Identifier):** Kernel-level identifier for OPS dossiers and async requests.
- **OPS:** Operation dossiers under `/rt/ops/**` that track multi-phase work (boot/shutdown, episodes, async jobs, control verbs).
- **PL/SQL (Procedural Language/SQL):** Referenced in onboarding guide for SQL-centric readers.
- **PRR (Pause/Rollback/Resume):** Control verbs that gate the heartbeat, rewind visibility, and then resume deterministically.
- **RO / RW:** Read-Only / Read-Write episode or access profiles.
- **RT (Runtime platform):** Core heartbeat, `/sys`/`/rt`/`/journal` runtime surfaces.
- **SER (Serialization):** Flat serializer stack (manifest/chunk records, AEAD/compression/history caps).
- **SIG (Signals):** Signal namespace (e.g., `sig_*` tables) used in the lexicon.
- **SVO (Security/Visibility Guard):** Branch guard (`cep_cell_svo_context_guard`) that enforces enclave branch policy and logs CEI/Decision Cells on risky cross-branch reads.
- **TEST:** Test harness fixtures/tags.
- **TLS (Transport Layer Security):** Generic secure transport layer; CEP treats TLS as a transport concern (not built into the kernel) when discussing encrypted providers.
- **TTL (Time To Live):** Beat-based expiry used for watchers and mailboxes.
- **UAF (Use-After-Free):** Memory safety bug where code writes/reads a freed allocation; recent CPS async fixes guard against this.
- **UBSan (UndefinedBehaviorSanitizer):** Compiler sanitizer for UB; runs are split from ASAN/Valgrind.
- **URL (Uniform Resource Locator):** External references treated as opaque strings/payloads by CEP.
- **UTF (UTF-8):** Encoding mentioned in native-type handling.
- **VM (Virtual Machine):** Host/guest environment term; also used for upper-layer Flow VM concepts (planned).

## Pipeline terms
- **Pipeline block:** `{pipeline_id, stage_id, dag_run_id, hop_index}` carried in envelopes/CEI/federation/enzyme contexts to tag work with its pipeline stage.
- **Pipeline preflight:** `sig_sec/pipeline_preflight` enzyme that approves pipeline specs under `/data/<pack>/policy/security/pipelines/**`.

## Federation terms
- **Mount:** A configured transport endpoint under `/net/mounts/<peer>/<mode>/<mount>/` with caps, provider, serializer policy.
- **Provider:** Transport implementation (sockets, pipes, mocks) registered with capability bits (CRC32C/deflate/AEAD/comparator, unreliable).
- **`upd_latest`:** Mount opt-in allowing unreliable transports to drop stale gauges, keeping only the most recent payload.

## Persistence and storage
- **Branch controller:** Per-branch policy/dirty tracker (often dubbed CPCL) deciding when and how to flush to CPS.
- **History RAM windows:** In-RAM retention knobs (`history_ram_beats`, `history_ram_versions`) controlling cached history.
- **Snapshot RO:** Read-only snapshot mode sealing a branch for immutable access.
- **Hydration:** Loading evicted cells/stores back into RAM (from CPS/CAS) for use in enzymes; `cep_cell_hydrate_for_enzyme` enforces policy/budget/Decision Cell guards.

## Heartbeat and control
- **Capture → Compute → Commit:** Beat phases; inputs freeze in Capture, work runs in Compute, state publishes in Commit at N+1.
- **Impulse:** Heartbeat-dispatched signal targeting enzymes; may carry pipeline metadata.
- **Watcher:** Awaiter on an OPS dossier state/status; fires as `op/cont` or `op/tmo`.

## Security
- **Decision Cell:** Recorded choice (e.g., cross-branch volatile read) used to keep replay deterministic.
- **Enclave:** Named trust zone plus trust tier; policies live under `/sys/security/**`.
- **Gateway:** Whitelisted enzyme for cross-enclave entry; checked against edges and pipeline approvals.

## Async I/O
- **Async request:** `io_req/**` entries describing outstanding async operations; completions land during Compute.
- **Channel:** Async handle (file/socket/KV) registered with the reactor; tracked under `io_chan/**`.
- **Reactor:** Async backend (native or shim) managing channels and completion queues.

## Miscellaneous
- **Crown jewel:** Informal term for sensitive branches (e.g., `/sys/security/**`) guarded by enclave/SVO policy and extra CEI/ledger evidence.
- **Glob bit:** Marker on tags/IDs that act as patterns (`*`), persisted so replay keeps intent.
- **Valgrind:** Memcheck tool used for leak/UAF detection on non-asan builds.
- **Lexicon:** Tag catalog in `docs/CEP-TAG-LEXICON.md`; extend it before minting new tags.
- **Namepool:** Intern table for domains/tags/strings, keeping IDs stable across runs.
