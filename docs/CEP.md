# Cascade Evolutionary Processing (CEP)

A living, evolving platform for deterministic work, supervised learning, and self‑modifying systems.

---

## 1) What CEP is

CEP is a **layered, evolving platform** for building applications that:

* run deterministically and are fully replayable,
* learn over time under **supervision**,
* and can **modify their own behavior and structure** safely—up to and including orchestrating upgrades of the CEP kernel itself.

At the base, CEP is a kernel that keeps small truths steady: facts are immutable, every change is linked to its causes, and every run can be replayed. On top of that, CEP hosts an **ecosystem of modules**—enzymes, organs, flows, and policies—that:

* operate within **finite action sets** (e.g., “pick variant A vs B vs C,” “apply one of these control moves”),
* expose **parameters/settings** that can be tuned,
* and are updated in response to **context and feedback** (labels, rewards, human input).

These modules behave like species in an ecosystem:

* **Variants** explore different tactics,
* **Species** group related variants,
* **Niches** route contexts to suitable variants,
* **Organisms** are running instances of tactics in specific situations,
* **Guardians** enforce invariants and safety margins,
* and **selection** promotes or retires variants based on supervised signals and observed performance. 

Humans stay in the loop at multiple levels:

* In **Layer 3**, they **curate datasets, inspect perspectives, add labels, override decisions, and annotate what the system is learning**. Think dashboards, labeling tools, experiment browsers.
* In **Layer 4**, they **propose and approve changes, define safety policies, decide which variants may dominate, and supervise CEP’s own upgrades**—including pipelines that roll out new kernel binaries or pack versions.

Because the kernel is implemented in portable C and intended for use with a permissive license, CEP can treat its own source, configurations, and binaries as first‑class artifacts: it can **orchestrate its own upgrade pipelines**, while governance and human supervisors ensure changes are safe, reversible, and well‑explained.

Everyday analogy: CEP is like a city whose infrastructure (roads, power, zoning) is stable and replayable, but where shops, services, and even the city charter itself evolve. Some agents try new tactics; the community observes, rewards, or shuts them down; and the city can even renovate its own infrastructure when enough evidence and trust has accumulated.

---

## 2) Technical Details

This section maps the story above onto concrete layers and subsystems, highlighting where ecosystem roles and human supervision live, and what currently ships versus what is planned.  

### 2.0 Layer Overview and Adoption

CEP is organized into five conceptual layers:

* **Layer 0 – Kernel & Pipeline Substrate**
  Deterministic heartbeats, cells, stores, enzymes, OPS, async I/O, persistence (CPS), CAS, federation, and security/enclave policy.
  L0 also carries lightweight **pipeline metadata** (pipeline/stage IDs) but does not interpret pipeline graphs or learning logic itself. This is the **only layer that currently ships**. 

* **Layer 1 – Coherence & Pipeline Graphs**
  Beings, bonds, contexts, and facets for durable identity and structure, plus **pipelines as graphs**: which stages exist, how they connect, what data they route, and where supervised signals and configuration live.

* **Layer 2 – Ecology & Flows (Modules and Evolution)**
  A deterministic Flow VM and ecological layer. Here, modules are treated as **species** with **variants** operating in **niches** (contexts). Flows implement tactics (Guard/Transform/Wait/Decide/Clamp) that add and update L1 pipeline graphs and L0 operations, under supervision. This is where evolutionary roles—organisms, species, variants, niches, guardians—live. 

* **Layer 3 – Awareness, Datasets & Human Interaction**
  Perspectives, interpretations, conventions, and summaries built over cells, pipelines, and flows. This is the layer that presents **human‑facing views and tools**: analytics dashboards, dataset browsers, labeling and review UIs, override controls, and annotation channels.

* **Layer 4 – Governance, Safety & Self‑Evolution**
  Laws, reforms, councils, provinces, and stories. This governs how CEP and its modules—and even the CEP kernel and packs—are allowed to change. Humans act as supervisors, reviewers, signers, and storytellers over the system’s evolution.

**Adoption path**

1. Start with **L0** only: use CEP as a deterministic kernel with storage, basic pipeline tagging, and security/federation.
2. Add **L1** when you need durable identities, relationships, and explicit multi‑stage pipelines.
3. Add **L2** to turn those pipelines into a **learning ecosystem**: modules as finite‑action policies, variants, niches, and supervised updates.
4. Add **L3** to give humans rich views, datasets, and interactive controls for monitoring and supervision.
5. Add **L4** to govern changes, including **self‑modification and upgrade pipelines** that can recompile and roll out new CEP components under human oversight.

Layer 0 must always bootstrap and shut down with **no packs present**; L1–L4 are optional packs that use public L0 APIs and must fail gracefully if absent. 

---

### 2.1 Core Rhythm: Heartbeats (Capture → Compute → Commit)

CEP advances in **beats**, each following a strict three‑phase contract:  

1. **Capture** – Ingest new cells and impulses; freeze the input set for beat *N*.
2. **Compute** – Enzymes and episodes read ≤ *N* and stage outputs:

   * new application state,
   * logged decisions,
   * training examples and loss metrics,
   * candidate parameter updates.
3. **Commit** – Publish staged outputs atomically as beat *N + 1*.

Properties:

* No mid‑beat visibility: observers only see fully committed beats, never partial state.
* **Determinism with exploration and learning**:

  * Any non‑deterministic choice (policy pick, RNG draw, variant selection, model sampling) must emit a **Decision Cell**.
  * Any learning‑driven parameter update must be recorded as new cells, with links to the data and decisions that produced it.
  * On replay, CEP consumes recorded decisions and parameter versions instead of re‑sampling or re‑training, so results match.

All heartbeat plumbing—agenda logs, impulse journals, stage notes, beat timestamps—lives in Layer 0 under `/rt/**` and `/journal/**`.  

---

### 2.2 Layer 0 – Kernel & Pipeline Substrate

Layer 0 is the shipping kernel. It provides the deterministic substrate, state management, security, and federation that all higher‑level logic and learning rely on.

#### 2.2.1 Truth Substrate: Cells, Stores, History

* **Cells**

  * Immutable facts with metadata, optional payloads (`cepData`), and optional child stores.
  * Append‑only timelines: corrections create new cells; history is retained or pruned explicitly. 
  * Provenance‑by‑construction: derived cells link to their parents, code identities (enzymes/organs), and Decision Cells when relevant.

* **Stores and Branches**

  * Stores: dictionary, list, packed queue, tree, hash, octree, etc., chosen per workload. 
  * Branches: durable subtrees under `/data/<branch>`, with independent persistence policies and metrics. 

* **Persistence and CAS**

  * CPS emits per‑beat flat frames (CRC32C, Merkle root, optional AEAD/compression) to branch storage engines. 
  * Large payloads land in CAS (`/cas/**`), referenced by hash so cells can stay compact.

Parameters, models, and configuration knobs for learning live in branches as just more cells, with full history and provenance.

#### 2.2.2 Enzymes, Episodes, and Modules at the Kernel Level

* **Enzymes**

  * Descriptors registered in `/enzymes/**` define callbacks, match policies (exact/prefix), dependency lists, and idempotency hints. 
  * Bindings attach descriptors to subtrees; tombstones mask inherited bindings to keep resolution deterministic.

* **Episodic Enzyme Engine (E³)**

  * Long‑running work is tracked as episodes (`op/ep`) under `/rt/ops/**`. 
  * Episodes run slices with budgets and cancellation; they can span many beats (for example, background training jobs or multi‑stage pipeline runs).

At L0, CEP is agnostic to “modules” in the learning sense—it just provides enzymes, cells, branches, locks, episodes, and provenance. L2 will interpret combinations of these as **modules with finite actions** and tunable parameters.

#### 2.2.3 Async I/O, Persistence, and Replay

* **Async I/O fabric**

  * Requests and completions are recorded under `/rt/ops/<op/io>`, with deterministic fields: state, deadlines, byte counts, errno, telemetry links. 
  * A reactor backend (portable or native) drives completions; results become visible during Compute to keep ordering deterministic.

* **CPS persistence**

  * `cps_storage_commit_current_beat()` streams dirty branches into flat frames and hands them to an engine (e.g. flatfile) that guarantees beat‑atomic commits. 
  * Metrics and readiness live under `/data/persist/<branch>/**`. 

* **Replay**

  * Any beat range can be re‑run with side effects disabled. Decision Cells and persistence logs ensure equality with the original run, even when learning was active.

#### 2.2.4 Federation, Security, and Pipeline Substrate

* **Federation transports and organs**

  * Transports register capability bitmaps; mounts choose providers and options.
  * Link/mirror/invoke organs manage cross‑peer relationships and data flows under `/net/**`. 

* **Enclave security and pipeline preflight**

  * Security policy under `/sys/security/**` defines enclaves, allowed edges, gateway enzymes, and budget/rate ceilings. 
  * A preflight enzyme validates **pipeline graphs** written by packs under `/data/<pack>/policy/security/pipelines/**` and stamps approvals; cross‑enclave pipeline invocations are refused if unapproved or over budget.

* **Pipeline metadata plumbing**

  * L0 allows OPS envelopes, CEI facts, async I/O requests, and CPS commits to carry:

    * **`pipeline_id`** – logical pipeline identifier (e.g. `coh/user_save_doc`, `learn/feed_ranking`).
    * **`stage_id`** – logical stage identifier within the pipeline (e.g. `PrepareFeatures`).
  * The kernel does not interpret these IDs; it:

    * propagates them end‑to‑end,
    * enforces enclave and pipeline policies,
    * and records them for diagnostics and replay.

Higher layers own **pipeline graphs** and **learning semantics**; L0 ensures that when a pipeline runs—local or federated—it does so deterministically and within policy.

---

### 2.3 Layer 1 – Coherence & Pipeline Graphs (Planned Pack)

Layer 1 adds **structure, identity, and routing** on top of the kernel.

#### 2.3.1 Beings, Bonds, Contexts, Facets

* **Beings** – long‑lived identities: users, documents, accounts, services, models, datasets, pipelines.
* **Bonds** – typed relations between beings: “owns,” “uses,” “depends_on.”
* **Contexts** – N‑ary relations, e.g. `(user, model, dataset, environment)`.
* **Facets** – smaller truths implied by contexts (permissions, roles, cohort membership).

Layer 1 maintains a **coherence ledger** (e.g. `/data/coh/**`) that enforces closure: required facets are created or recorded as deterministic debts, and adjacency mirrors speed up neighborhood queries. 

#### 2.3.2 Pipelines as Graphs

Layer 1 also owns the **pipeline graph**:

* **Pipelines as beings**

  * Each pipeline is a Being with identity, owner(s), lifecycle, and province membership (for example, which deployment environment it lives in).
* **Stages as beings or bonds**

  * A stage can be modeled as a Being linked to its pipeline by a Bond or as a typed Bond (`pipeline ↔ stage`), depending on schema preferences.
  * Stage metadata includes:

    * referenced L0 enzyme or gateway enzyme,
    * input and output branches,
    * roles (e.g. “example,” “prediction,” “label,” “update”),
    * references to parameter cells or config branches.
* **Edges as contexts**

  * Contexts connect stages: “stage A feeds stage B under conditions C.”
  * Facets on these contexts encode routing conditions, filters, and triggers.

Both **application pipelines** (e.g. request handling) and **learning pipelines** (e.g. training/evaluation) are first‑class graph objects here.

#### 2.3.3 From Structure to Execution

Given current cells and coherence:

* L1 decides which pipeline stages are “ready”:

  * for example, a new event, a complete example+label pair, or a scheduled batch window.
* L1 emits L0 operations/signals tagged with `pipeline_id` and `stage_id`:

  * enzyme dispatch locally,
  * federation invokes for remote stages,
  * episodes for multi‑beat work.

L1 does not define how tactics (learning strategies, explorations) work; that’s L2’s job. It simply says **what exists**, **how it is connected**, and **when it should run**.

---

### 2.4 Layer 2 – Ecology & Flows (Modules and Evolution) (Planned Pack)

Layer 2 provides the **ecological and algorithmic layer**: it defines how modules behave, learn, and evolve within the structures of L1 and the substrate of L0.

#### 2.4.1 Flow VM

A **Flow** is a deterministic state machine built from five primitives: 

* **Guard** – pure preconditions on contexts and cells.
* **Transform** – emit new cells (facts, predictions, losses, updates).
* **Wait** – suspend until a pattern/impulse appears (e.g. “wait for labels”).
* **Decide** – choose a branch via a policy; always emit a Decision Cell.
* **Clamp** – enforce budgets, timeouts, and parallelism limits.

Flows compile to:

* updates to L1 pipeline graphs (creating/removing stages, changing bindings),
* and L0 operations (enzyme invocations, episodes, federation invokes).

#### 2.4.2 Ecosystem: Species, Variants, Niches, Organisms

Layer 2 reintroduces CEP’s ecological concepts explicitly: 

* **Species** – Families of flows or modules that solve the same task (e.g. different ranking algorithms).
* **Variants** – Concrete implementations or parameterizations within a species (e.g. `Ranker_v1`, `Ranker_v2`).
* **Niches** – Contextual regions where certain variants are preferred (e.g. new users, heavy users, specific geos).
* **Organisms** – Individual flow/module instances executing in specific contexts (e.g. “Ranker_v2 handling this user+session”).
* **Guardians** – Invariants and safety constraints that veto unsafe actions or configurations.

Selection pressures come from:

* supervised labels and rewards,
* metrics from L3 (performance, fairness, cost),
* and policies defined in L4.

Layer 2 uses Decision Cells, parameter cells, and pipeline metadata to make this ecosystem deterministic and replayable.

#### 2.4.3 Modules as Finite‑Action Policies with Supervision

In CEP, a **module** is typically:

* given a **context** (i.e. a set of beings and facets from L1),
* allowed to pick an action from a **finite action set** (e.g. [A, B, C]),
* evaluated later via **supervision** (labels, rewards, human feedback),
* and updated under **learning rules** encoded in flows.

Layer 2 flows ensure that:

* each action choice is recorded as a Decision Cell, with context and variant identity,
* each label/feedback is linked back to the decisions and parameters that produced it,
* each parameter update is recorded as new cells with full provenance.

This creates a **supervised evolutionary ecosystem** in which:

* variants compete within niches,
* guardians enforce invariants,
* and selection is driven by explicit evidence.

---

### 2.5 Layer 3 – Awareness, Datasets & Human Interaction (Planned Pack)

Layer 3 makes CEP **aware of its own behavior and data**, and exposes that awareness to humans.

#### 2.5.1 Perspectives, Interpretations, Summaries

* **Perspectives** – Materialized views over:

  * pipeline runs and stage health,
  * module/variant performance,
  * decision distributions,
  * datasets and label coverage.
* **Interpretations** – Tags and scores (e.g. “high risk,” “drifting,” “under‑sampled cohort”).
* **Conventions** – Stable patterns promoted to default behavior (e.g. “variant B is now canonical for cohort C”).
* **Summaries** – Aggregated metrics over time frames (beats → minutes → hours → days), with links back to raw evidence. 

These artifacts live as derived cells in branches (e.g. `/data/awareness/**`), built incrementally from heartbeat outputs.

#### 2.5.2 Human‑Facing Interaction Surfaces

Layer 3 is the primary **human interaction zone**:

* **Dashboards & analytics**

  * Visualize perspectives and summaries: model performance, data drift, error breakdowns, pipeline bottlenecks.
* **Dataset browsers**

  * Let humans inspect examples, labels, and outcomes, with full provenance.
* **Labeling & feedback tools**

  * Support human‑in‑the‑loop supervision: adding labels, re‑labeling, attaching explanations, or marking outliers.
* **Override and triage controls**

  * Allow humans to:

    * override decisions,
    * disable or down‑weight variants,
    * pause pipelines or flows,
    * schedule re‑training or backfills.
* **Annotation and storytelling hooks**

  * Let humans attach narratives, notes, or hypotheses to runs, datasets, or incidents (feeding into Layer 4 stories).

Technically, these tools talk to CEP via APIs and mailboxes, but conceptually:

> Layer 3 is where humans **see**, **judge**, and **shape** the system’s behavior, day‑to‑day.

---

### 2.6 Layer 4 – Governance, Safety & Self‑Evolution (Planned Pack)

Layer 4 governs how CEP, its modules, and even its kernel are allowed to change.

#### 2.6.1 Laws, Reforms, Councils, Provinces

* **Laws** – Signed, versioned bundles that can encode:

  * schemas and policies,
  * allowable pipeline structures,
  * constraints on learning (e.g. max update frequency, fairness criteria),
  * rules for kernel/pack upgrades and rollbacks.
* **Reforms** – Structured change plans:

  * migrating from one law set or pipeline to another,
  * with pre‑checks, post‑checks, and compensating actions.
* **Councils** – Governance workflows that mix human and automated roles:

  * proposing changes,
  * reviewing evidence (L3 perspectives),
  * voting, and enacting.
* **Provinces** – Namespaced sandboxes:

  * `prod`, `staging`, `shadow`, `experimental`,
  * each with its own subset of laws, pipelines, and species. 

Humans at Layer 4 are:

* authors of laws and reforms,
* members of councils,
* approvers and signers of critical changes,
* and narrators of how the system evolved.

#### 2.6.2 Self‑Evolution and Kernel Upgrades

CEP is implemented as a C kernel with a permissive license in mind, which means:

* Its **source code, builds, and binaries** can be treated as ordinary artifacts.
* CEP itself can host **upgrade pipelines** that:

  * build new kernel or pack versions,
  * run them through tests and shadow runs,
  * gather metrics and human feedback via L3 perspectives,
  * and, if approved by a council, roll them out gradually across provinces.

A typical self‑evolution workflow:

1. A council proposes a new kernel or pack version (e.g. enabling a new store type or learning primitive).
2. L2/L3 assemble **evidence**: performance data, test results, safety analyses.
3. L4 encodes a **reform**:

   * how to deploy the new binaries,
   * which provinces to try first,
   * rollback conditions.
4. CEP runs an **upgrade pipeline**:

   * episodes in L0 coordinate I/O, rollouts, and monitoring,
   * old and new kernels may run side‑by‑side in different provinces.
5. If KPIs and safety checks pass, councils approve broader rollout; if not, the reform rolls back.

Crucially:

* CEP **does not randomly mutate its own C code**. Changes to the kernel and packs are governed by explicit laws, reforms, and human approvals.
* All upgrade steps are encoded as cells, operations, and decisions, so the system’s own evolution is replayable and auditable.

---

### 2.7 Observability, Privacy, and Replay

**Observability**

* Every derived fact links back to:

  * sources,
  * guards and policies,
  * code identities (enzymes/flows/species),
  * and Decision Cells. 
* OPS dossiers under `/rt/ops/**` track operations, including:

  * kernel boot/shutdown, persistence, async I/O,
  * episodes and pack‑defined ops (training jobs, upgrades).
* CEI facts capture:

  * severity (`fatal`, `crit`, `usage`, `warn`, `debug`),
  * topic, note, origin, subject links,
  * and optional attachments. 

**Privacy**

* Payload‑level cryptography with per‑subject keys:

  * encrypted payloads with secmeta,
  * erasure by dropping keys while preserving stubs,
  * optional redaction cells for reversible masking. 

**Replay**

* Any beat range can be re‑run with side effects disabled.
* Decision Cells remove randomness from replays.
* Training, evaluation, selection, and even upgrade workflows are represented as cells and decisions, so the system’s evolution is reproducible.

---

### 2.8 Scale and Federation

CEP scales by **partitioning** data and work across branches and runtimes:

* Each partition has its own heartbeat and `/data/**` subtree, persisted by CPS. 
* Cross‑partition and cross‑enclave interactions use:

  * federation transports and mounts,
  * link/mirror/invoke organs,
  * and enclave security with pipeline preflight. 

The platform avoids global barriers; instead, it relies on:

* local determinism per partition,
* eventual alignment of summaries and perspectives,
* and governance at L4 to coordinate large‑scale changes.

---

### 2.9 Minimal Viable CEP (Revised Stack)

You can adopt CEP gradually:

1. **Layer 0 – Kernel & Pipeline Substrate**

   * Deterministic kernel, heartbeat, cells, stores, CAS, CPS, federation, security.
   * Optional pipeline tagging via `pipeline_id` / `stage_id`.

2. **Layer 1 – Coherence & Pipeline Graphs**

   * Identity, relationships, pipeline definitions and graphs.

3. **Layer 2 – Ecology & Flows**

   * Modules as finite‑action policies, flows, species/variants/niches, supervised evolutionary behavior.

4. **Layer 3 – Awareness & Human Interaction**

   * Perspectives, datasets, dashboards, labeling/feedback tools, manual overrides.

5. **Layer 4 – Governance & Self‑Evolution**

   * Laws, reforms, councils, provinces, and narrative artifacts governing both application behavior and CEP’s own upgrades.

At each step, CEP remains **deterministic, replayable, and explainable**.

---

### 2.10 Worked Example: Supervised Learning Pipeline with Evolution and Human Oversight

Consider a feed ranking application with supervised learning, evolution of variants, and human oversight.

#### Beat 100 – Capture

```text
Event#view1 { user=alice, items=[i1,i2,i3], context=home_feed }
```

Layer 0 records this event under `/data/app/events/**`.

#### Layer 1 – Coherence & Pipeline Graph

* Beings: `user:alice`, `model:feed_ranking`, `dataset:home_feed`.
* Context ties them, with facets capturing roles and cohort.
* Pipeline `FeedRanking` has stages:

  1. `PrepareFeatures`
  2. `ScoreItems`
  3. `LogExample`
  4. `AwaitLabel`
  5. `ApplyUpdate`

L1 routes `Event#view1` into stage `PrepareFeatures` and emits an L0 operation with:

* `pipeline_id=learn/feed_ranking`,
* `stage_id=PrepareFeatures`.

#### Layer 2 – Ecology & Flow

A Flow `RankFeed` belongs to species `feed_ranking` with variants `v1`, `v2`, `v3`.

* Guard ensures data/model availability.
* Transform builds item features.
* Decide picks a variant among `v1`, `v2`, `v3`, emitting a Decision Cell and recording the chosen variant and niche (e.g. “home_feed_first_session”).
* Transform scores items using the chosen variant.
* Clamp enforces latency and CPU budgets.

Layer 2 logs:

* a **prediction** (ranking),
* a **training example** cell referencing:

  * context,
  * chosen variant,
  * parameters used,
  * Decision Cell.

#### Layer 0 – Execution and Persistence

In Compute for beat 100, L0 executes:

* the enzymes implementing `PrepareFeatures`, `ScoreItems`, `LogExample`,
* possibly as an episode if you want a multi‑step slice.

In Commit for beat 101:

* examples, predictions, and decision logs become visible,
* CPS persists them.

#### Beat 102 – Capture: Supervision Arrives

```text
Event#click1 { user=alice, item=i2, label=clicked, context=home_feed }
```

L1 joins `click1` to the logged example via coherence (same user/session) and routes it to stage `AwaitLabel`, then `ApplyUpdate`.

Layer 2’s flow `TrainFeed`:

* Waits for example+label,
* Computes loss and gradient,
* Emits parameter update cells under `/data/learn/models/feed_ranking/params/**`,
* Logs a Decision Cell if any randomization (e.g. learning rate) occurs.

L0 applies the update deterministically in an episode.

#### Layer 3 – Human Interaction

Operators see, via perspectives:

* per‑variant performance (CTR, calibration),
* data skew across cohorts,
* label quality indicators.

They can:

* add labels,
* re‑label misclassified examples,
* mark cohorts as risky,
* down‑weight or disable a variant via overrides.

These choices are logged as cells and CEI facts, feeding back into L2 flows (e.g. adjusting priors or gating species).

#### Layer 4 – Governance & Self‑Evolution

A council notices that `feed_ranking:v3` consistently outperforms `v1` and `v2` in some provinces, with no regressions on safety metrics.

They propose a **reform**:

* promote `v3` as default species in `prod` province,
* gradually retire `v1` and `v2`,
* and at the same time roll out a new kernel pack that optimizes the feature store.

The reform encodes:

* rollout steps (shadow → partial → full),
* rollback triggers,
* metrics to monitor (from L3).

CEP runs an **upgrade pipeline**:

* episodes in L0 coordinate building new binaries, deploying them to staging, and switching mounts,
* L3 perspectives feed live data to the council,
* if conditions are met, the council approves broad rollout.

All of this—decisions, metrics, rollouts, rollbacks—is recorded as cells and OPS/CEI evidence, so the **system’s evolution** is just as traceable and replayable as any individual prediction.

---

### 2.11 Glossary

**Physiology (L0)**

* **Cell** – Immutable fact with metadata, payload, and child stores.
* **Store** – Data structure for child sets (dictionary, list, tree, hash, etc.).
* **Branch** – Durable subtree under `/data/<branch>`.
* **Enzyme** – Deterministic worker bound to cells.
* **Episode (op/ep)** – Long‑running operation tracked across beats.
* **Heartbeat** – Capture → Compute → Commit rhythm.
* **Pipeline substrate** – Kernel‑level pipeline/stage metadata and enforcement hooks.

**Coherence & Pipelines (L1)**

* **Being** – Long‑lived identity (user, model, dataset, pipeline, province).
* **Bond** – Typed relation between beings.
* **Context** – N‑ary relation tying beings with role‑typed positions.
* **Facet** – Smaller truth implied by a context.
* **Pipeline (graph)** – Connected set of stages and edges over beings and contexts.
* **Stage** – A step in a pipeline bound to an L0 enzyme or gateway.

**Ecology & Flows (L2)**

* **Flow** – Deterministic state machine (Guard/Transform/Wait/Decide/Clamp).
* **Module** – Flow‑backed component that chooses actions from a finite set.
* **Species** – Family of flows/modules addressing the same task.
* **Variant** – Concrete implementation/parameterization of a species.
* **Niche** – Contextual domain where certain variants are preferred.
* **Organism** – An instance of a flow/module executing in a specific context.
* **Guardian** – Safety gate enforcing invariants and vetoing unsafe actions.
* **Decision Cell** – Recorded choice (for exploration, policy picks, etc.).

**Awareness & Human Interaction (L3)**

* **Perspective** – Materialized view over data, pipelines, and flows.
* **Interpretation** – Tag/score capturing risk, quality, or health.
* **Convention** – Stabilized pattern promoted to default.
* **Summary** – Aggregated rollup of metrics with pointers to sources.

**Governance & Self‑Evolution (L4)**

* **Law** – Signed, versioned bundle of schemas and policies.
* **Reform** – Structured change with checks and compensations.
* **Council** – Group/process that proposes, reviews, and approves changes.
* **Province** – Namespaced sandbox/deployment environment.
* **Story / Legend / Myth** – Narrative artifact tied back to CEP evidence.
