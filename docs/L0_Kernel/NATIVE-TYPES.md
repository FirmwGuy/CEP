# CEP L0 Native Types (Bootstrap)

This note defines the minimal, built‑in data types for CEP Layer 0 (Kernel). It balances two needs: making the kernel deterministic and replayable today, while leaving room for rich, user‑defined types in higher layers tomorrow.

---

## 1) Plain‑Language Intro

Think of CEP as a careful librarian. At the bottom layer, the librarian must file cards in a way that is always the same anywhere in the world. To do that, the cards need a tiny, universal label that says what kind of thing is on the card and how to sort it, without reading any extra books.

That tiny label is our L0 “native type.” It’s not the whole story about the data (units, meaning, domain rules). It’s just enough to store, compare, and replay it exactly. The rich meaning lives in higher layers, where we can use normal CEP cells to describe schemas, units, and relationships.

To bootstrap cleanly, we keep L0 very small and practical:
- Simple truth values (yes/no).
- Whole numbers and real numbers in common sizes.
- Text as UTF‑8.
- Vectors: ordered lists of numbers or bytes (used for things like stream chunks). If you’ve heard “blob,” think of that as a vector of bytes – vector is just less opaque and more honest.

This lets CEP run deterministically from day one, while still welcoming richer, user‑defined types above.

---

## 2) Technical Specification

Goal: provide a minimal, canonical descriptor that L0 can use to validate, compare, hash, and store values without consulting other cells. Everything else (schemas, units, domains) remains in L1+ as cells.

### 2.1 Binary Types (L0)

L0 defines a minimal set of binary types, encoded directly in `cepData`:
- BOOLEAN
- UNSIGNED (8/16/32/64‑bit)
- INTEGER (8/16/32/64‑bit)
- FLOAT (binary32/binary64)
- UTF8 (as octets)
- Internal: DT, PATH (as vectors of 64‑bit units)

These correspond to the `_cepBinType` enum in the code. Shape (scalar vs vector) is orthogonal and is expressed by the `vector` flag inside `cepData`.

Out of scope at L0: matrices, decimal floating point, arbitrary precision; represent them via vectors or at higher layers. HASH values use `vector<UINT8>` with agreed length; specific algorithms belong to upper layers.

### 2.2 Widths and Sizes

- Integers: 8/16/32/64 bits.
- Floats: 32/64 bits (binary32/binary64).
- BOOL: 1 byte canonical storage (values 0x00 or 0x01).
- VECTOR: element width implied by its base type; total byte length carried by the data representation and must be an exact multiple of element size.

Note: If you need 128‑bit integers or hashes at L0, represent them as `VECTOR<UINT8>` length 16/32 and add semantics at L1+.

### 2.3 Canonical Encoding

- Endianness: numerics are stored in canonical little‑endian form inside `cepData` bytes (both VALUE and DATA). On write/update, values are converted to LE; comparisons and hashing always use these canonical bytes.
- TEXT_UTF8: stored as given after UTF‑8 validation; no Unicode normalization at L0. Comparison and hashing are bytewise.
- BOOL: stored as single byte 0x00 (false) or 0x01 (true).
- VECTOR: element bytes are individually canonicalized (e.g., LE per element for numeric element types). For `VECTOR<UINT8>`, bytes are as‑is.

### 2.4 Shape

- L0 supports two shapes, encoded by `cepData.vector`:
  - Scalar: a single value (BOOLEAN, INTEGER/UNSIGNED, FLOAT, UTF8 in rare cases).
  - Vector: rank‑1 array of a base element type (including `UINT8` for raw bytes, UTF‑8 bytes, or 64‑bit units for DT/PATH).
- Length of a vector is derived from payload size divided by element size; no embedded dimension field is required at L0.
- Safety: Internal types `DT` and `PATH` are always vectors. `cep_data_new()` asserts that `vector == true` when `bintype` is `DT` or `PATH`.

### 2.5 Data Header

All information the kernel needs to validate, store, and compare values lives inside `cepData`:
- `datatype`: VALUE | DATA | HANDLE | STREAM
- `bintype`: one of `_cepBinType` (BOOLEAN, UNSIGNED, INTEGER, FLOAT, UTF8, DT, PATH)
- `vector`: boolean flag indicating scalar vs vector shape
- `writable` and `lock`: mutability controls
- `encoding`: optional binary encoding id (reserved for future use)
- `size` / `capacity`: payload sizes in bytes
- `hash`: cached content hash (implementation detail)
- `_dt` (`domain`, `tag`): L0 naming (for the data cell itself)

This compact header is sufficient for L0 operations; richer semantics (units, schemas, constraints) are modeled as normal cells at higher layers.

### 2.6 Comparison and Hashing

Total order and hashing are required for deterministic storage/indexing:
1) Compare by family, then shape, then widths (and element widths for vectors).
2) Compare by canonical bytes:
   - Numerics: compare element bytes in LE.
   - Text/UTF8: bytewise (no normalization at L0).
   - Bool: 0x00 < 0x01.
   - Vectors: lexicographic compare of element‑canonical bytes.
3) Hash is computed over the tuple (descriptor fields) + canonical bytes.

NaN handling: for `FLOAT_BIN`, preserve bit‑patterns; comparisons are lexicographic on canonical bytes. Upper layers may impose semantic rules (e.g., ordering of NaNs) if desired.

### 2.7 Data Representations Interop

`cepData` supports four forms (VALUE, DATA, HANDLE, STREAM):
- VALUE/DATA: store canonical bytes per sections above; validate size on write.
- HANDLE/STREAM: carry the same `bintype`/`vector` info; staged windows for streams must match vector element sizing (commonly `vector<UINT8>`). Journaling and preconditions follow the I/O Streams note.

### 2.8 Vectors vs “Blobs”

We standardize on VECTOR terminology at L0:
- `vector<UINT8>` is the precise, minimally opaque form often called a “blob.”
- Using VECTOR keeps typed arrays and raw bytes under one concept and avoids hiding structure that may matter (e.g., `VECTOR<FLOAT_BIN/32>`).

### 2.9 Upper Layers (L1+) Interop

- Rich schemas, units, domains, field names, and composite types are expressed as normal CEP cells and bonds in L1+.
- Data cells may also carry a higher‑level type reference (e.g., `@type → CEP:domain/type@v1`) without affecting L0 behavior.
- Unknown or custom types remain usable at L0 as TEXT/VECTOR/INT/FLOAT — always deterministically comparable and replayable.

---

## 3) Q&A

Q: Why not store all type info as cells instead of a built‑in descriptor?
A: L0 must validate, compare, and hash values without chasing other cells. A tiny descriptor avoids circular dependencies and keeps the kernel deterministic and small. Rich meaning still lives as cells in upper layers.

Q: Will this block user‑defined types like complex numbers or meshes?
A: No. Represent complex numbers as `VECTOR<FLOAT_BIN/32>` length 2 (or 64‑bit). Meshes can be trees of vectors: positions as `VECTOR<FLOAT_BIN/32>` length 3N, indices as `VECTOR<UINT/32>`, with a higher‑layer schema describing structure. L1+ can add a `@type` reference to a schema cell for introspection.

Q: What about 128‑bit hashes or IDs?
A: Use `VECTOR<UINT8>` of the required length (16, 32, 64 bytes). If you need to name the algorithm (e.g., SHA‑256), attach that meaning at L1 via a `@type` or attribute cell.

Q: Decimal vs hexadecimal floats?
A: Presentation only. L0 stores IEEE binary32/64 canonical bytes; both decimal and hex text forms parse to the same stored value. If you need decimal floating point semantics, model them in L1+, or propose a future `FLOAT_DEC` extension.

Q: Why little‑endian canonicalization?
A: It yields stable bytes and hashes across architectures with simple, fast code. Endianness differences vanish at the boundary; comparison and hashing are uniform.

Q: Can we add matrices or other shapes later?
A: Yes. Start with SCALAR and VECTOR at L0. Matrices and richer shapes can be added later as an additive, backward‑compatible extension or modeled as vectors today.

Q: Does UTF‑8 validation change the bytes?
A: No. L0 only validates that the sequence is valid UTF‑8 and stores the bytes as‑is. No normalization is applied at L0; upper layers may add normalization policies if desired.

Q: How does this help streams and external I/O?
A: Streams naturally use `VECTOR<UINT8>` windows with offsets and lengths. The same canonicalization and hashing rules apply, enabling deterministic journaling and replay as defined in the I/O Streams document.

Q: Won’t this duplicate information at higher layers?
A: Intentionally yes, but with different roles. L0’s descriptor ensures safe storage and replay. L1+ adds human/domain meaning. They align, not conflict: L1 types can restate or refine L0 expectations.
