# CEP Licensing Overview

This project adopts a pragmatic, developer‑friendly licensing model:
the core library is licensed under the Mozilla Public License 2.0 (MPL‑2.0),
while most test code is dedicated to the public domain for friction‑free reuse.

---

## Technical Details

- Core library (production code): MPL‑2.0
  - All sources under `src/l0_kernel/` (and subfolders) are covered by MPL‑2.0.
  - The top‑level `LICENSE` file contains the full text of the MPL‑2.0.
- Test sources (except `munit.*`): Public domain (CC0 1.0)
  - All files under `src/test/` excluding `src/test/munit.c` and `src/test/munit.h`
    are dedicated to the public domain using the CC0 1.0 Universal dedication.
  - This allows you to copy test scaffolding into your own projects without attribution.
- munit (test harness only): MIT
  - We provide the µnit Testing Framework (`src/test/munit.c`, `src/test/munit.h`) for
    building and running tests. These files are MIT‑licensed by their author(s) and
    retain their original license headers.
  - The library build does not install or ship munit; it is used only for test binaries.
  - See the repository `NOTICE` file and the license headers in `munit.h` for details.

Distribution notes:
- If you redistribute the test binaries or their sources, keep the munit MIT notices.
- If you redistribute only the built library and public headers, no test code is included.

---

## Global Q&A

- Why MPL‑2.0 for the core?
  - MPL offers file‑level copyleft: improvements to CEP files must remain open,
    but your broader application can remain under your chosen license.

- Can I use CEP in closed‑source or commercial software?
  - Yes. You must satisfy MPL‑2.0 for any modified CEP files (provide source for those files),
    but you can combine them with proprietary code in a Larger Work.

- What do I need to do about munit’s MIT license?
  - Nothing if you only ship the library. If you distribute test binaries or their sources,
    include the MIT notice; the vendored files already contain the full text.

- Why are tests (except munit) public domain?
  - To make it easy for others to copy patterns, fixtures, and helpers without attribution friction.

- How are contributions licensed?
  - Unless explicitly stated otherwise, contributions are accepted under MPL‑2.0 for the core.
    Test code contributions (excluding `munit.*`) are dedicated to the public domain (CC0 1.0).

