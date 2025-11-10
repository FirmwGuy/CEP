# Vendored BLAKE3

Source: https://github.com/BLAKE3-team/BLAKE3 (commit `c54ee7e60d98418e50fd355a3be835edef107f65`, 2024-09-04).

Files copied from `c/` in that repository:

- Core C sources: `blake3.c`, `blake3_dispatch.c`, `blake3_portable.c`, `blake3_neon.c`.
- SIMD backends: `blake3_sse2.c`, `blake3_sse41.c`, `blake3_avx2.c`, `blake3_avx512.c`,
  plus x86-64 Unix assembly shims (`*_x86-64_unix.S`).
- Public headers: `blake3.h`, `blake3_impl.h`.
- Licenses: `LICENSE_A2` (Apache-2.0) and `LICENSE_CC0`.

## Build configuration inside CEP

- **Debug builds** (`meson setup -Dbuildtype=debug …`): CEP defines `BLAKE3_NO_SSE2`,
  `BLAKE3_NO_SSE41`, `BLAKE3_NO_AVX2`, `BLAKE3_NO_AVX512`, and `BLAKE3_USE_NEON=0`
  so the runtime executes the portable scalar path. This keeps single-step debugging sane and
  avoids mixing host SIMD states with instrumentation like ASAN.
- **Optimized builds** (non-`debug`): CEP enables architecture-specific backends.
  - `x86_64`: assemble the SSE2/SSE4.1/AVX2/AVX-512 Unix `.S` files; the dispatcher picks
    the widest instruction set supported at runtime.
  - `aarch64`: compile `blake3_neon.c` so NEON codepaths are available.
  - Other architectures fall back to the portable implementation.

If you need to change this policy, edit the `blake3_*` block in the top-level `meson.build`.
