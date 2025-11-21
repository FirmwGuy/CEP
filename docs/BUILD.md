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
| `zlib_provider` | combo (`auto`, `system`, `bundled`) | `auto` | Prefer the system zlib; fall back to the bundled CRC32/Deflate snapshot when unavailable. |
| `executor_backend` | combo (`stub`, `threaded`) | `stub` | Select the episodic executor backend. The threaded backend spins a worker pool on POSIX/Windows platforms; wasm/emscripten builds automatically fall back to `stub`. |

Set options during `meson setup` or after the fact with `meson configure`:

```bash
meson setup build -Dasan=true -Dtests=enabled
# …or later
meson configure build -Dcode_map=true
```

### Compression / CRC provider

CEP’s flat serializer, CRC helpers, and optional Deflate container all rely on zlib.

- `-Dzlib_provider=auto` (default) discovers a system zlib via pkg-config. If it exists, CEP links against it and defines `CEP_ZLIB_SYSTEM`.
- If no system zlib is detected (or you pass `-Dzlib_provider=bundled`), Meson compiles the vendored snapshot under `src/third_party/zlib/` (upstream zlib **1.3.1.1**) and defines `CEP_ZLIB_BUNDLED`.
- `-Dzlib_provider=system` is strict: configuration fails when pkg-config cannot locate zlib.

The bundled copy ships the full upstream sources (crc32, deflate/inflate, gz* utilities) so the build stays reproducible on platforms without a native package. See `NOTICE` and `docs/LICENSING.md` for the zlib license text and provenance expectations.

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
  - `-Dexecutor_backend=stub` keeps the cooperative queue bound to the heartbeat (deterministic, single-threaded).
  - `-Dexecutor_backend=threaded` launches a worker pool sized to the available CPUs and preserves TLS budgeting/cancellation semantics. The option requires pthreads (or the Win32 thread primitives surfaced via `cep_sync.c`). wasm/emscripten builds auto-downgrade to `stub` even when the option is forced.

## Offline Fallback (No Meson/Ninja)

- Use the emergency Makefile under `unix/Makefile`.
  - Build dir is isolated at `build-make/` to avoid clobbering the Meson build.
  - Build: `make -C unix`
- Run: `../build-make/bin/cep_tests --log-visible debug`
- Clean: `make -C unix clean`
- Notes: This fallback compiles the core library sources into the test executable.

## Sanitizer Builds

- Create a dedicated build directory so the sanitized compiler flags never leak into your everyday build:
  ```bash
  meson setup build-asan -Dasan=true
  meson compile -C build-asan
  ASAN_OPTIONS="detect_leaks=1" meson test -C build-asan --no-rebuild
  ```
  Use Clang when possible—its sanitizer runtimes are more complete, especially on MSYS2/Windows.

## Valgrind Runs

- You can reuse the regular (non-ASAN) build and wrap the test harness:
  ```bash
  MESON_TEST_WRAPPER="valgrind --leak-check=full --show-leak-kinds=definite --error-exitcode=1 \
    --suppressions=tools/valgrind.supp" meson test -C build --no-rebuild
  ```
  The suppression file is intentionally minimal; keep it in sync with upstream toolchain updates and add entries only for false positives.

## Enclave Validation Workflow

Keep the Enclave resolver, telemetry, and diagnostics in sync by running this matrix whenever policy-sensitive code changes:

1. **Lexicon sanity:** `python3 tools/check_unused_tags.py`
2. **Targeted unit suites:**
   ```bash
   meson test -C build cep_unit_tests --test-args "--single /CEP/fed_security/analytics_limit"
   meson test -C build cep_unit_tests --test-args "--single /CEP/fed_security/pipeline_enforcement"
   meson test -C build cep_unit_tests --test-args "--single /CEP/branch/security_guard --no-fork --param timeout 120 --show-stderr"
   meson test -C build cep_unit_tests --test-args "--single /CEP/fed_invoke/decision_ledger"
   ```
3. **Full sweeps:**  
   `meson test -C build --timeout-multiplier 3 --no-rebuild`  
   `meson test -C build-asan --timeout-multiplier 3 --no-rebuild`
4. **Valgrind batches:** run federation suites in groups of ≤3 selectors (e.g., `/CEP/fed_security/*`, `/CEP/fed_link/*`, `/CEP/fed_mirror/*`, `/CEP/fed_invoke/*`) and archive results under `build/logs/valgrind_*.log`. Keep integration POC fixtures separate—they hold locks longer but should still be captured (`valgrind_integration_poc_{integration,focus}.log`).

These commands are referenced throughout the Enclave design/topic docs; updating this section keeps the rest of the documentation stable.

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
