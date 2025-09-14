CEP Build Guide

Introduction

CEP is a C library with a small test executable. You can build it on Windows (MSYS2 UCRT64) and Linux (Manjaro) using Meson and Ninja. If you’re not a programmer: Meson prepares the build plan, and Ninja runs the fast, incremental compilation. All temporary files stay inside a build folder so your source files remain clean.

Getting Started (Simple)

- Windows (MSYS2 UCRT64 shell)
  - Install tools: `pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-meson mingw-w64-ucrt-x86_64-ninja`
  - Configure: `meson setup build`
  - Build: `meson compile -C build`
  - Run tests: `meson test -C build`

- Manjaro Linux
  - Install tools: `sudo pacman -S --needed gcc meson ninja`
  - Configure: `meson setup build`
  - Build: `meson compile -C build`
  - Run tests: `meson test -C build`

What Gets Built

- Library: `cep` built from sources under `src/l0_kernel/` (e.g., `cep_cell.c`).
- Executable: the unit test harness under `src/test/` builds a single program named `cep_tests` in the `build/` folder, linked against the library.
- Note: Files `cep_enzyme.*` and `cep_heartbeat.*` are intentionally excluded from the build.

Developer Details

- Compiler flags
  - Defaults include `-g -Wall` and `-fplan9-extensions` (when supported), plus `_DNU_SOURCE`.
  - On Windows only, tests add `__STDC_NO_ATOMICS__` to work around a munit atomics quirk; Linux builds don’t use this define.

- Sanitizers (optional)
  - Enable with: `meson setup build -Dasan=true`.
  - Recommended with Clang on MSYS2 UCRT64; supported with GCC/Clang on Manjaro.

- Cleaning builds
  - Out-of-source: remove the entire `build/` folder: `rm -rf build/`.

- IDEs
  - Many IDEs understand Meson; or configure an external build with `meson compile -C build`.

Q&A

- Why Meson instead of raw Makefiles?
  - Meson is portable, fast (via Ninja), and keeps build artifacts out of your source tree with minimal configuration.

- Do I need Clang?
  - No. GCC is enough. Clang is optional for extra diagnostics, sanitizers, and tooling (`clang-tidy`, `clang-format`).

- Where are the build outputs?
  - Binaries are placed in the `build/` folder (e.g., `build/cep_tests[.exe]`).

- Can I build in a different folder?
  - Yes. For example: `meson setup out/win-ucrt64 && meson compile -C out/win-ucrt64`.

- How do I run tests?
  - `meson test -C build` runs the suite and prints results.

Build Variants and Options

- Static vs Shared library
  - Default is static: `meson setup build`.
  - Shared only: `meson setup build -Ddefault_library=shared`.
  - Both: `meson setup build -Dboth_libs=true` (produces static and shared).

- Tests on/off
  - Disable: `meson setup build -Dtests=disabled`.
  - Enable (default): `meson setup build -Dtests=enabled`.

- Optional CEP server (standalone)
  - Enable: `meson setup build -Dserver=enabled`.
  - Meson expects a `src/server/main.c` entry point; if it’s missing, the build prints a warning and skips the server.

Offline Fallback (No Meson/Ninja)

- Use the emergency Makefile under `unix/Makefile`.
  - Build dir is isolated at `build-make/` to avoid clobbering the Meson build.
  - Build: `make -C unix`
  - Run: `../build-make/bin/cep_tests --log-visible debug`
  - Clean: `make -C unix clean`
  - Notes: This fallback compiles the core library sources into the test executable. It intentionally excludes `cep_enzyme.*` and `cep_heartbeat.*`.
Notes
- Optional sanitizers: `meson setup build -Dasan=true` (best with Clang on MSYS2 UCRT64).
