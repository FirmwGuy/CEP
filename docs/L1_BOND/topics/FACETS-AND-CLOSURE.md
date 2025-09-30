# L1 Topic: Facets and Closure Guarantees

## Introduction
Facets turn relationships into promises. When a context appears, facets make sure every required follow-up—an audit log, a notification, or a derived record—actually happens. This topic explains how Layer 1 tracks those promises and keeps them honest.

## Technical Details
### Declaring facets
- Context specs list required facet tags alongside role assignments. Each entry may include configuration data copied into the facet payload.
- During `cep_context_upsert`, missing facets are enqueued under `/bonds/facet_queue` with pointers back to the source context, the triggering op count, and the context label for diagnostics.

### Dispatching work
- Registered plugins advertise the facet tags they handle. `cep_facet_dispatch` matches enqueued items to plugins and runs them inside the heartbeat, preserving ordering and determinism.
- Plugins are responsible for writing the derived record under `/data/CEP/L1/facets/<tag>/<context-key>` and committing any side effects back into the kernel or higher layers. `cep_tick_l1` updates queue state (`pending`, `complete`, `fatal`) after each dispatch so retries remain visible.

### Handling retries
- Each queue entry tracks attempt counts and the last error. Failures leave the item in place with a bumped counter so `cep_tick_l1` can retry on the next beat while preserving the diagnostic label.
- Exponential backoff is available; plugins can set the next eligible heartbeat to avoid hammering flaky dependencies.
- Operators can mark a facet as permanently failed by writing a resolution note into the queue entry and acknowledging it as part of an incident workflow; `cep_tick_l1` will stop dispatching once the queue state flips to `fatal`.

## Q&A
- **Can a plugin generate multiple facets at once?** It may, but each derived record must still correspond to a single facet entry. Register additional facets if you need separate lifecycles.
- **How do I avoid infinite retries?** Use the attempt counter to cap retries and escalate failures to an alerting enzyme once the threshold is met; the queue state (`pending`, `fatal`) makes it easy to spot items that exceeded the policy.
- **What if a context is deleted?** The heartbeat prunes facet queue entries for retired contexts, ensuring work does not run against stale data.
- **Can facets fan out to higher layers?** Yes. Plugins can emit new impulses or write into Layer 2+, but they should remain idempotent and anchor their work to the originating context key.
