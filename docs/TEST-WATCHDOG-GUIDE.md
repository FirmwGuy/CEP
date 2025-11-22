# CEP Test Watchdog Guide

When long-running tests stall, the watchdog is what yanks them back. This primer explains how the harness keeps suites from hanging forever and the knobs you can twist while chasing regressions.

## Technical Details

- `test_watchdog_create(seconds)` arms a background thread that calls `_Exit()` once the negotiated timeout elapses; Layer 0 Organ Validation Harness (OVH) suites default to 240 s but you can override the budget with the `timeout=` Munit parameter.
- The max clamp sits at 300 s (`WATCHDOG_MAX_TIMEOUT_SECONDS`), so multi-minute diagnostics can run with an appropriately high ceiling without bypassing the kill switch.
- Set `TEST_WATCHDOG_TRACE=1` to mirror armed/cleared/expired events on `stderr`, including elapsed seconds since arming; traces respect the default 1 s granularity.
- The shared `test_ovh_watchdog_setup/tear_down` fixture arms watchdogs for `/CEP/heartbeat/bootstrap`, `/CEP/organ/sys_state`, and `/CEP/organ/rt_ops`, ensuring they signal completion before teardown.
- You can still request a shorter runtime by passing `timeout=60` (or similar) through Meson: `meson test -C build-asan-linux --test-args="--param timeout 60"`.

## Global Q&A

- **How do I see when the watchdog fires?** Export `TEST_WATCHDOG_TRACE=1` before launching the suite; the harness will print `[watchdog] armed`, `[watchdog] cleared`, or `[watchdog] expired` with elapsed seconds.
- **Can I run a suite longer than five minutes?** Not without changing the clamp; the ceiling is intentionally capped at 300 s to prevent runaway jobs in CI. If you truly need more, adjust `WATCHDOG_MAX_TIMEOUT_SECONDS` locally.
- **Do I have to touch every test to use the watchdog?** No—OVH suites already share a fixture. For other suites, call `test_watchdog_create()` in your setup and `test_watchdog_destroy()` in teardown to adopt the same pattern.
