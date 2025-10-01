# L1 Topic: Facets and Closure Guarantees

## Introduction
Facets let contexts promise follow-up work—logging an edit, notifying collaborators, building rollups. Layer 1 keeps track of those promises by creating placeholder records and queue entries that your facet enzymes resolve.

## Technical Details
### Declaring facets
- Add facet tags to the `cepContextSpec::facet_tags` array when calling `cep_context_upsert`.
- The helper writes placeholder facet records under `/data/CEP/CEP/L1/facets/<facet>/<hash>` with `facet_state=pending` and copies the context label into `value`.
- It also queues a work item under `/bonds/facet_queue/<facet>/<hash>` with `value=<context label>` and `queue_state=pending`.

### Registering handlers
- Use `cep_facet_register` to pair a facet tag with the context tag it applies to and the enzyme that materialises it.
- Policies are stored but not executed yet; the callback’s return code controls the queue outcome.

### Dispatch flow
1. `cep_tick_l1` iterates each queue entry once per call.
2. It invokes the registered enzyme with paths pointing at the queue entry and the facet record.
3. Based on the return code:
   - `CEP_ENZYME_SUCCESS` → facet record `facet_state=complete`, queue entry `queue_state=complete`, entry removed after the pass.
   - `CEP_ENZYME_RETRY` → both stay `pending` for the next pass.
   - `CEP_ENZYME_FATAL` → facet record `facet_state=failed`, queue entry `queue_state=fatal`.
   - Missing handler → queue entry `queue_state=missing` and left in place.
4. Empty queue families are removed to keep the workspace neat.

### Operating tips
- Keep facet enzymes idempotent. They may be retried if they return `CEP_ENZYME_RETRY`.
- If you need richer diagnostics, write them into the facet record (e.g., under `meta/`) before returning an error code.
- Call `cep_tick_l1` regularly so the queue depth stays manageable.

## Q&A
- **Where do attempt counters live?** They do not exist yet. Track attempts yourself (for example, write a counter into the facet record) if it matters today.
- **Can a facet handler enqueue more facets?** Yes. Just make sure you avoid infinite loops by checking whether the derived state already exists before queuing new work.
- **How do I cancel a facet?** Remove the queue entry and adjust the facet record manually. Record why you skipped it so future audits make sense.
- **What if multiple context tags share the same facet tag?** Register each pair separately. The dispatcher treats (`facet_tag`, `context_tag`) as the unique key.
