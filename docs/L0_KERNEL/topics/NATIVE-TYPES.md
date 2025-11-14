# L0 Topic: Native Types

This note defines how native data works in CEP Layer 0 (Kernel). At L0, a value is only bytes plus a tiny label. The real meaning of those bytes lives above the kernel, where you can describe and evolve types as normal CEP cells.

---

## 1) Intro

Imagine a storage box with a sticky label. The box holds some bytes; the label says just enough so future tools know what to do with the box, without forcing the storage system to open it. In CEP’s kernel, that label is a cepDT (a compact “domain:tag” name), and the contents are opaque bytes.

Examples of labels (tags) you might use:
- math:INT32, math:FLOAT64
- geom:VECTOR3D, img:RGBA8
- text:UTF8, hash:SHA256

The kernel doesn’t interpret those bytes. Enzymes (code that knows the domain) and higher layers decide what a tag means. This keeps the kernel small and predictable, while letting meaning, schemas, and conversions evolve freely in upper-layer packs.

---

## 2) Technical Specification

Goal: make L0 deterministic and simple by treating payloads as opaque bytes and attaching only a cepDT tag. All rich typing (fields, units, constraints, shapes) is modeled in upper-layer packs as regular cells and links.

### 2.1 Data Model at L0

- Payload: a byte sequence (`size` bytes). No built‑in numeric/text/vector types. No element width or shape encoded at L0.
- Tag: `cepDT` = (domain, tag). A compact name used for ordering and for higher‑layer routing/meaning.
- Representation: `cepData` may store bytes inline or on the heap, and may also be a HANDLE/STREAM. In all cases, the payload is opaque; the cepDT travels with the data cell as its name.

### 2.2 What L0 Does (and Doesn’t) Do

- Does: store bytes; compare and hash deterministically; keep the cepDT; move/copy/update byte buffers; record/stream bytes.
- Doesn’t: validate semantics (endianness, UTF‑8, IEEE754), track element width, or enforce shapes (scalar/vector/matrix). Those are enzyme/upper-layer packs concerns.

#### Secured payloads (secdata)

- `secdata/` keeps encrypted and/or deflated VALUE/DATA buffers resident in RAM. Every `cepData` now carries a `secmeta` snapshot (`enc_mode`, `codec`, `key_id`, `payload_fp`, `raw_len`, `enc_len`) plus the nonce/AAD hash used to seal the bytes so serializers and CPS can emit the exact ciphertext without re-encoding.
- Inline VALUE payloads are automatically externalised whenever `enc_mode != none`, forcing encrypted revisions through `payload_chunk` records and preventing inline metadata from leaking ciphertext.
- Public helpers (`cep_data_set_plain/enc/cenc/cdef`, `cep_data_unveil_ro/done`, `cep_data_rekey`, `cep_data_recompress`) drive the secure pipeline, zero scratch slabs on release, and emit CEI topics (`enc_fail`, `dec_fail`, `rekey_fail`, `codec_mis`) whenever sealing or unveiling fails.

### 2.3 Deterministic Ordering and Hashing

To index and sort payloads deterministically, L0 defines a stable hash without inspecting semantics:
- Hash: combine `cepDT` metadata with the payload bytes (`H = Hash(domain || tag || size || bytes)`). This keeps VALUE vs DATA/handles deterministic even when several indexes coexist.

Note that the user-facing cell ordering helpers honour the storage/indexing strategy in effect. For example, name-indexed stores use `cep_dt_compare` (domain/tag), while historical traversal relies on timestamps plus tombstone status to preserve append-only sequencing. Treat hashes as payload fingerprints, not a global cell ordering rule.

### 2.4 Endianness, Encoding, and Canonicalization

L0 doesn’t canonicalize numeric/text formats. Enzymes that write bytes for a given tag are responsible for choosing and documenting a canonical form (e.g., little‑endian for `math:INT32`, IEEE‑754 binary64 for `math:FLOAT64`, UTF‑8 for `text:UTF8`).

Guidelines for enzyme authors:
- Pick a canonical byte format per tag and stick to it.
- Prefer little‑endian for numerics unless domain requirements say otherwise.
- For text, prefer UTF‑8 bytes; normalization rules (if any) belong in upper-layer packs.

### 2.5 Upper-Layer Type Descriptions (Optional but Recommended)

While the cepDT is enough for the kernel, higher layers can attach richer meaning in normal CEP ways:
- Schema cells: a child link like `@type → /types/math/INT32@v1` describing width, range, and encoding.
- Composite definitions: cells describing structures (e.g., `geom:VECTOR3D` = 3 × `math:FLOAT32`).
- Validation policies: enzymes can validate payloads against schemas during reads/writes.

The kernel remains unaware of these attachments; it just stores and orders bytes.

### 2.6 Interop with HANDLE/STREAM

- HANDLE: opaque external resource; still carries a cepDT. Any materialization to bytes must produce the same canonical bytes for its tag.
- STREAM: windows of bytes over time; windows are tagged and remain opaque. Journaling/replay uses the same bytewise hashing and ordering.

### 2.7 Backward Compatibility Notes

Older drafts enumerated built‑in binary types (BOOLEAN, INT32, FLOAT64, UTF8, DT/PATH) and vector shapes. These are expressed as tags over opaque bytes. Suggested mappings:
- BOOLEAN → `core:BOOL` with bytes 0x00 or 0x01.
- INT32 → `math:INT32` with 4 bytes in chosen endianness (recommend LE).
- FLOAT64 → `math:FLOAT64` with IEEE‑754 8 bytes.
- UTF8 → `text:UTF8` with raw UTF‑8 bytes (validation in enzyme/upper-layer packs).
- PATH/DT → represent as regular cells and links; when serialized to bytes, use explicit tags like `core:PATH` with a documented encoding.

---

## 3) Practical Examples

- geom:VECTOR3F — 12 bytes, three float32 values in LE. An enzyme that understands `geom:*` can read/write these floats; the kernel only stores 12 bytes.
- hash:SHA256 — 32 bytes of digest. Any tool that knows `hash:SHA256` can validate the size; L0 treats it as just 32 bytes.
- text:UTF8 — arbitrary length bytes. Rendering or normalization lives in enzymes; L0 uses bytewise compare and hash.

### 2.8 Namepool Diagnostics Guardrails

Namepool growth now emits `sev:crit` CEI facts whenever page or bucket allocation fails, but those emissions are gated until the kernel lifecycle scope is marked ready. The bootstrap sequence (`cep_namepool_bootstrap`) runs before the diagnostics mailbox exists, so helpers call `cep_lifecycle_scope_is_ready(CEP_LIFECYCLE_SCOPE_KERNEL)` before logging failures. Leave that guard in place whenever touching namepool internals so bootstrap callers do not trip fatal diagnostics while the runtime is still wiring up `/data/mailbox/diag`.

---

## Global Q&A

Q: Why make native data opaque?
A: To keep the kernel small, deterministic, and future‑proof. Opaque bytes avoid a built‑in type explosion and push meaning to upper-layer packs, where it can evolve without touching L0.

Q: How do we ensure interoperability if L0 doesn’t canonicalize?
A: By agreeing on canonical bytes per tag and writing them via enzymes. The cepDT identifies the convention; bytes carry the value.

Q: Can I mix endianness for the same tag?
A: You can, but you shouldn’t. Pick one per tag (usually LE) so hashing, diffs, and equality remain stable.

Q: What happens if an enzyme doesn’t recognize a tag?
A: Nothing breaks. The data remains comparable and storable. Unrecognized tags are simply opaque to that enzyme.

Q: How do I model vectors, matrices, or structs now?
A: Use upper-layer packs schemas and tags (e.g., `geom:VECTOR3F`, `linalg:MATRIX4x4F32`) and document the byte layout. The kernel doesn’t need to know the shape.

Q: Does L0 still validate UTF‑8 or numbers?
A: No. Validation is up to enzymes and upper-layer packs. L0 compares and hashes bytes only.

Q: What about external handles and streams?
A: They remain supported as opaque representations. When materialized or journaled, they must produce consistent bytes for their tag, so replay remains deterministic.
