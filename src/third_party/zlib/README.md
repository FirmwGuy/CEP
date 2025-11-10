# Vendored zlib (CRC32)

- Source: https://github.com/madler/zlib (commit `5a82f71ed1dfc0bec044d9702463dbdf84ea3b71`, 2024-10-08).
- Files copied verbatim from upstream `crc32.c`, `zlib.h`, `zconf.h`, `zutil.h`, plus the upstream `LICENSE` and `README` (stored as `README.upstream`).
- Build policy inside CEP:
  - **Default (`zlib_provider=auto`)** — Meson tries to link against the system `zlib` shared library via pkg-config. If found, CEP uses it for CRC routines.
  - **Bundled fallback** — When no system zlib is available (or `-Dzlib_provider=bundled`), CEP builds `crc32.c` directly and exposes the same API internally. Debug builds pass `-DZLIB_INTERNAL` just like upstream.
  - **Force system** — `-Dzlib_provider=system` errors if pkg-config cannot locate zlib, providing a deterministic build knob.
- Only the CRC32 implementation is compiled; compression/decompression entry points are unused.
