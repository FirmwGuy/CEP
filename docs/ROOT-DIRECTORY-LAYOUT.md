# CEP Root Directory Layout

## Introduction
Picture CEP as a living campus. The kernel keeps the utilities humming, Bonds orchestrates how people and projects relate, and higher layers teach, govern, and remember. The campus only works if everyone knows where to file work in progress, what gets archived, and how to find the story later. This guide describes the shared directory layout that all layers rely on so the campus stays orderly even as it grows.

## Technical Details
### Overview
Every CEP installation exposes a deterministic tree rooted at `/`. Each top-level folder is a dictionary keyed by `cepDT` so names replay in a stable order. Layer 0 owns the mechanics of the tree, but Layers 1 and above rely on the same locations for provenance, impulses, and governance.

```
/
  sys/       — platform facts and constants
  rt/        — in-beat runtime state
  bonds/     — Layer 1 indices and coherence helpers
  enzymes/   — enzyme registry and capability manifests
  env/       — handles and streams to the outside world
  journal/   — append-only evidence of every heartbeat
  cas/       — content-addressable payload store
  data/      — durable application state (visible at N+1)
  stories/   — layer 3+ summaries, narratives, and projections
  law/       — governance artifacts for layers 4–5
  tmp/       — ephemeral scratchpad outside the heartbeat rhythm
```

### sys/ – Platform Facts
- **Purpose**: centralizes beat counters, configuration toggles, schema anchors, and naming tables shared by all layers.
- **Layer touchpoints**:
  - L0 seeds heartbeat counters here and reads budgets.
  - L1 registers namespace roots (e.g., `/sys/namespaces/l1`) and caches selectors.
  - L3+ publishes projection manifests so downstream consumers know which perspectives exist.
- **Storage mode**: dictionary with small VALUE/DATA cells; immutable configuration changes append new revisions automatically.

### rt/ – Runtime State Per Heartbeat
- **Purpose**: contains everything volatile during beat `N` until the commit edge. Structures under `rt/beat/N/*` vanish after roll-over.
- **Layer touchpoints**:
  - L0 heartbeats create inboxes, agendas, staging buffers, and token ledgers.
  - L1 queues coherence work (`rt/beat/N/bonds/work`) and tracks impulse cursors waiting to flush.
  - L2+ flows pin their cursors and budget usage here before emitting decisions.
- **Storage mode**: lists for queues (`inbox`, `agenda`, `stage`), dictionaries for budgets and metrics, catalogs when sorted access is required.

### bonds/ – Layer 1 Working Set
- **Purpose**: houses adjacency caches, facet work queues, and impulse cursors that Layer 1 maintains outside the core `/CEP/L1/*` data tree.
- **Contents**:
  - `/bonds/adjacency`: mirrors of per-being bond lists for fast lookup.
  - `/bonds/facet_queue`: packed queue of contexts or bonds awaiting facet expansion.
  - `/bonds/checkpoints`: heartbeat checkpoints for impulse delivery.
- **Storage mode**: dictionaries keyed by being or context ids; packed queues for worklists. Writes follow the same append-only semantics as L0 directories.

### enzymes/ – Capability Registry
- **Purpose**: durable manifest of enzyme contracts, budgets, and adapter bindings.
- **Layer touchpoints**:
  - L0 uses the metadata to enforce domain restrictions at schedule time.
  - L1 references declared read/write domains when validating bond materialization.
  - Governance layers read version history before approving upgrades.
- **Storage mode**: dictionary per enzyme (`/enzymes/<name>`) containing `io`, `policy`, `impl`, and `version` sub-dictionaries.

### env/ – External Interfaces
- **Purpose**: structured handles into filesystems, message buses, sensors, or other systems.
- **Layer touchpoints**:
  - L0 enforces HANDLE/STREAM invariants and journals intent hashes.
  - L1 stores lightweight links to env resources when a bond references an external artifact.
  - L3+ perspectives refer back to env handles for live dashboards.
- **Storage mode**: dictionaries keyed by adapter; child nodes are HANDLE or STREAM cells validated on access.

### journal/ – Evidence Ledger
- **Purpose**: append-only record of reads, intents, and outcomes per beat.
- **Layer touchpoints**:
  - L0 records kernel-level provenance here (`/journal/beat/N/{reads,intents,outcomes}`).
  - L1 appends impulse manifests (`/journal/beat/N/bonds`) so Layer 2 can replay social changes deterministically.
  - L4 councils audit proposals and reforms against the same journal entries.
- **Storage mode**: dictionaries by beat number; within each beat use lists for chronological order. Append-only invariants enforce replay safety.

### cas/ – Content Addressable Store
- **Purpose**: immutable stash of blobs keyed by hash.
- **Layer touchpoints**:
  - L0 stores large payloads to avoid duplicating DATA cells.
  - L1 facets stash derived payload templates here.
  - L3 summaries reference CAS hashes when emitting narratives or projections.
- **Storage mode**: directory tree partitioned by hash prefix; optional `pins/` dictionary tracks retention policies.

### data/ – Durable Application State
- **Purpose**: final state exposed to the world. Writes arrive via the N→N+1 commit edge.
- **Layer touchpoints**:
  - L0 commits staged mutations here after journal checks.
  - L1 persists beings, bonds, contexts, and facets under `/CEP/L1/*`, anchored beneath `data/` so the entire CEP namespace lives in one durable subtree.
  - L2 flows attach their organism state under `/CEP/L2/*`, and L3+ perspectives cache derived material alongside them.
- **Storage mode**: dictionaries for stable lookup; catalogs or lists where order matters. Cells carry full append-only history.

### stories/ – Narratives and Projections
- **Purpose**: staging area for Layer 3 cognition and Layer 5 culture: summaries, interpretations, stories, legends.
- **Layer touchpoints**:
  - L3 writes projections (`/stories/projections`) referencing data and journal hashes.
  - L5 narrators store chronicles and legends anchored in Layer 1 bonds.
- **Storage mode**: dictionaries by narrative type with VALUE/DATA cells for compact stories and links for richer material.

### law/ – Governance Records
- **Purpose**: houses Layer 4 councils, laws, reforms, and provinces.
- **Layer touchpoints**:
  - Councils record proposal state machines and voting logs here.
  - Provenance links point back to journal entries and CAS artifacts for accountability.
- **Storage mode**: dictionaries keyed by governing body or law id; catalogs capture decision timelines.

### tmp/ – Ephemeral Scratchpad
- **Purpose**: non-durable workspace for debugging or exploratory tools.
- **Layer touchpoints**:
  - Enzymes may dump instrumentation here.
  - Higher layers never depend on tmp content for decisions.
- **Storage mode**: simple insertion-ordered list; cleared at startup or per policy.

## Beat Lifecycle (N → N+1)
1. **Input**: impulses enter `/rt/beat/N/inbox`; Layer 1 may append coherence work into `/bonds/facet_queue`.
2. **Schedule**: agenda and token dictionaries under `/rt/beat/N` determine execution order.
3. **Execute**: enzymes read `/env` and `/data`; every access is journaled.
4. **Stage**: results accumulate under `/rt/beat/N/stage` and Layer 1 prepares adjacency updates under `/bonds/adjacency`.
5. **Commit**: intents are compared to preconditions; successful writes land in `/data`, CAS blobs are pinned, journals capture outcomes.
6. **Publish**: Beat `N+1` initialises with fresh runtime folders; Layer 2+ flows advance using the new data snapshot; stories and laws may pick up new events.

## Implementation Notes & Checklists
- **Storage discipline**: keep root folders as dictionaries; choose RB-tree storage when sorted iteration matters; use packed queues for worklists.
- **Determinism**: never mutate `tmp/`-derived information into durable decisions; resolve all runtime choices through journaled evidence.
- **Layer coordination**: when adding a new subsystem, decide whether it belongs under `data/`, `bonds/`, `stories/`, or `law/` before introducing new root folders to avoid fragmentation.
- **Testing**: simulate beats by replaying `journal/beat/N/*` and confirming `/data` and `/bonds` land in the same state.

## Q&A
- *Why keep Layer 1 helpers outside `/data`?*  
  The `bonds/` folder holds caches and queues that support coherence but are safe to rebuild; keeping them separate prevents accidental reliance on transient structures during replay.

- *Do higher layers write directly to `/rt/`?*  
  No. They request work via impulses or staged intents; only the heartbeat driver owns `/rt/*` mutations to preserve ordering.

- *How does this layout scale as new councils or storytellers appear?*  
  Add subdirectories under `law/` or `stories/` keyed by council or narrative; the root set stays unchanged so tooling can rely on a stable frame.

- *Can I merge CAS into `/data` for small deployments?*  
  You can, but separating large blobs keeps `data/` lean and lets you garbage-collect independently. Even in minimal builds the `cas/` namespace can remain empty without breaking contracts.

- *What prevents tmp artifacts from leaking into history?*  
  Commit logic enforces that only staged intents promoted from `/rt/beat/N/stage` reach `/data`. Any attempt to reference `/tmp` during commit is rejected by policy checks.
