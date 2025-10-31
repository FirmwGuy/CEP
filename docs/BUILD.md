# CEP Build Guide

## Introduction

CEP is a C library with a small test executable. You can build it on Windows (MSYS2 UCRT64) and Linux (Manjaro) using Meson and Ninja. If you’re not a programmer: Meson prepares the build plan, and Ninja runs the fast, incremental compilation. All temporary files stay inside a build folder so your source files remain clean.

## Getting Started (Simple)

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

## What Gets Built

- Library: `cep` built from sources under `src/l0_kernel/` (e.g., `cep_cell.c`).
- Executable: the unit test harness under `src/test/` builds a single program named `cep_tests` in the `build/` folder, linked against the library.

## Meson Configuration Options

The Meson project defines these switches (see `meson_options.txt`):

| Option | Type | Default | Notes |
| --- | --- | --- | --- |
| `asan` | boolean | `false` | Enable Address/Undefined sanitizers (great with Clang). |
| `code_map` | boolean | `false` | Generate ctags/cscope symbol maps (`meson compile -C build code_map`). |
| `docs_html` | boolean | `false` | Build the Doxygen/Graphviz HTML docs (`meson compile -C build docs_html`). |
| `tests` | feature | `enabled` | Build the unit tests (`enabled`, `disabled`, `auto`). |
| `server` | feature | `disabled` | Build the standalone CEP server (requires `src/server/main.c`). |
| `both_libs` | boolean | `false` | Produce both static and shared `libcep`. |
| `zip` | feature | `auto` | Toggle the libzip-backed stream adapter (`enabled`, `disabled`, `auto`). |
| `executor_backend` | combo (`stub`, `threaded`) | `stub` | Select the episodic executor backend. `threaded` is future work; wasm/emscripten builds automatically fall back to `stub`. |

Set options during `meson setup` or after the fact with `meson configure`:

```bash
meson setup build -Dasan=true -Dtests=enabled
# …or later
meson configure build -Dcode_map=true
```

## Developer Details

- Compiler flags
  - Defaults include `-g -Wall` and `-fplan9-extensions` (when supported), plus `_GNU_SOURCE`.
  - On Windows only, tests add `__STDC_NO_ATOMICS__` to work around a munit atomics quirk; Linux builds don’t use this define.

- Sanitizers (optional)
  - Enable with: `meson setup build -Dasan=true`.
  - Recommended with Clang on MSYS2 UCRT64; supported with GCC/Clang on Manjaro.

## Clang Build (Optional)

If you want extra diagnostics and better sanitizers, you can build with Clang.

- Install packages
  - Windows (MSYS2 UCRT64 shell):
    - `pacman -S --needed mingw-w64-ucrt-x86_64-clang mingw-w64-ucrt-x86_64-clang-tools-extra mingw-w64-ucrt-x86_64-compiler-rt`
    - Optional extras: `mingw-w64-ucrt-x86_64-clang-analyzer mingw-w64-ucrt-x86_64-include-what-you-use`
  - Manjaro Linux:
    - `sudo pacman -S --needed clang clang-tools-extra lld llvm compiler-rt compiler-rt-sanitizers`

- Configure with Clang
  - Using environment variable:
    - `CC=clang meson setup build-clang -Dasan=true`
  - Using Meson native file (in repo):
    - `meson setup build-clang --native-file toolchains/clang.meson -Dasan=true`

- Build and test
  - `meson compile -C build-clang`
  - `meson test -C build-clang`

- Cleaning builds
  - Out-of-source: remove the entire `build/` folder: `rm -rf build/`.

- IDEs
  - Many IDEs understand Meson; or configure an external build with `meson compile -C build`.


## Build Variants and Options

- Static vs shared library
  - Default build is static; use `-Dboth_libs=true` to emit both variants or `-Ddefault_library=shared` for a shared-only build.

- Tests
  - Disable the harness with `-Dtests=disabled`; keep it on (default) for routine development.

- CEP server
  - Opt in with `-Dserver=enabled`. Meson warns (and skips it) if `src/server/main.c` is absent.

- Code maps
  - Flip `-Dcode_map=true` to install the tooling rules. Invoke with `meson compile -C build code_map` and inspect the `build/code_map_*` artefacts.

- HTML docs
  - `-Ddocs_html=true` wires the target; run `meson compile -C build docs_html` to generate `build/docs/html/index.html`.

- Libzip adapter
  - Force on/off with `-Dzip=enabled|disabled`. The default `auto` builds when `libzip` is detected.

- Episodic executor backend
  - Cooperative stub backend ships today. Pass `-Dexecutor_backend=threaded` to opt into the forthcoming threaded backend; on wasm/emscripten builds Meson automatically falls back to the stub path.

## Offline Fallback (No Meson/Ninja)

- Use the emergency Makefile under `unix/Makefile`.
  - Build dir is isolated at `build-make/` to avoid clobbering the Meson build.
  - Build: `make -C unix`
  - Run: `../build-make/bin/cep_tests --log-visible debug`
  - Clean: `make -C unix clean`
  - Notes: This fallback compiles the core library sources into the test executable.
## Notes
- Optional sanitizers: `meson setup build -Dasan=true` (best with Clang on MSYS2 UCRT64).

## Debug Instrumentation

- Wrap any ad-hoc diagnostics in the `CEP_DEBUG_*` macros (see `src/l0_kernel/cep_molecule.h`) so debug prints build only when `CEP_ENABLE_DEBUG` is defined.

---

## Global Q&A

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
- How do I run just one test (or pass parameters)?
  - The harness uses [munit](https://nemequ.github.io/munit/) flags. Run the executable directly:
    - Discover tests: `./build/cep_tests.exe --list`
    - Run a single test: `./build/cep_tests.exe --single /CEP/heartbeat`
    - Pass parameters: `./build/cep_tests.exe --param boot_cycle after_reboot /CEP/heartbeat`
    - Fail fast / show stderr: `./build/cep_tests.exe --fatal-failures --show-stderr`
    - Set a deterministic seed: `./build/cep_tests.exe --seed 0x1234abcd`
    - Debug/instrument on Linux: `./build/cep_tests --no-fork` keeps execution in a single process so your debugger or probes do not lose track when munit would otherwise fork.
