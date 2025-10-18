# Organ Authoring Guide

## Introduction
Organs let you treat an entire subtree as a typed unit with clear lifecycle hooks. This guide explains how organ metadata is published, how the runtime enforces validator bindings, and how optional constructor/destructor enzymes are dispatched so authors can rely on deterministic workflows instead of ad-hoc glue.

## Technical Details
- **Descriptor registration.** Call `cep_organ_register` early in bootstrap with a `cepOrganDescriptor`. The descriptor defines a short `kind` label, the `organ/<k>` store tag, and the required/optional enzyme names (`org:<k>:vl`, `org:<k>:ct`, `org:<k>:dt`). Registration caches the descriptor in-memory and emits an immutable snapshot at `/sys/organs/<k>/spec/` with the fields `store`, `validator`, optional `ctor`/`dtor`, plus `kind` and `label`.
- **Immutable metadata.** Each `spec` branch is created inside a veiled transaction and sealed via `cep_branch_seal_immutable`. Once published, spec data cannot be rewritten, so observers can safely cache or compare descriptors across beats.
- **Binding enforcement.** `cep_cell_bind_enzyme` now consults the organ registry. When you bind on an organ root, the runtime requires `propagate=true`, insists the validator name matches the descriptor, and refuses to bind optional ctor/dtor unless the validator is already present. Attempts to unbind the validator are rejected so every organ keeps its mandatory guard.
- **Constructor/destructor dispatch.** The stock `sig_cell` enzymes detect organ roots. After a successful insert, `cep_organ_request_constructor` queues `op/ct` for the new root when a constructor is defined. During deletes, `cep_organ_request_destructor` queues `op/dt` and the `sig_cell` handler skips immediate removal so the destructor enzyme can tear down state (and ultimately delete) deterministically.
- **Validator wrapper.** `cep_organ_request_validation` locates the containing organ for any cell and enqueues `op/vl` against the root. The validator enzyme receives the impulse with the root as target, starts the appropriate OPS/STATES sequence, and closes with `sts:ok` or `sts:fail` once checks finish.

## Q&A
- **When should I register my organ descriptor?** Do it during bootstrap before binding enzymes. Registration must happen once; repeated calls return success only if the descriptor is identical.
- **What if my organ doesn’t need a constructor or destructor?** Leave the corresponding `cepDT` fields invalid (`{0}`). The runtime treats them as absent and the `sig_cell` enzymes become no-ops for that pathway.
- **How do I trigger validation on demand?** Call `cep_organ_request_validation(cell)` with any node inside the organ. It finds the root, enqueues `op/vl`, and the validator runs on the next beat without you having to build paths manually.
- **Why must I bind the validator with propagate=true?** Propagation ensures the validator executes for any impulse targeted within the organ subtree and keeps the contract that every organ root has an inheritable guard.
- **What happens if I try to unbind the validator?** The runtime rejects the request so that every organ retains its required validator. Optional bindings can still be tombstoned.
- **How does deletion behave when a destructor exists?** The delete enzyme only queues `op/dt` and returns. Your destructor enzyme receives the organ root intact and should soft-delete or remove it before closing the operation. If no destructor is registered, the default hard delete executes immediately.
