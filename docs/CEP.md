# Cascade Evolutionary Processing (CEP)

A living, replayable platform for deterministic work, supervised learning, and self‑modifying “minds” built from small cooperating policies.

---

## 1) What CEP is

CEP is a **layered runtime** for building systems that:

* run under a strict **heartbeat** (Capture → Compute → Commit),
* keep **perfect, replayable history** of what they did and why,
* **learn** by adjusting tiny policy tables instead of opaque models,
* and can **change their own behavior and structure** under explicit governance.

At the bottom, CEP is a C kernel that acts like physics: it stores immutable facts (“cells”), moves bytes to and from the world deterministically, and enforces security and federation rules. 

On top of that, optional packs add:

* **Coherence** – beings, bonds, and pipeline graphs that say *what exists* and *how stages connect*. 
* **Ecology & Flows** – a **Flow VM** with species/variants/niches, where each module is a finite‑action policy that logs every choice as a Decision Cell.  
* A **learning vocabulary**:

  * **Grounders** – modules that ground CEP in the external world (I/O, UI, devices).
  * A shared **Signal Field** – compact global signals derived from metrics and CEI.
  * **Focus Frames** – small *peepholes* over that field + local context, used by each learner.
  * **Playbooks** – per‑context tables that map Focus Frames to finite action sets and stats.
  * **Mode Clusters** – recurrent patterns in the Signal Field + flow activity; attractor‑like “system moods.”
  * **Imaginate** – controlled sampling from Playbooks for exploration, guided by past outcomes. 

Above that, CEP treats its own behavior as data:

* **Awareness** – perspectives, datasets, dashboards, and “operator panels” that show humans a curated slice of what CEP is doing.
* **Governance** – laws, reforms, councils, and provinces that decide how CEP and its packs are allowed to change, including **upgrade pipelines** that roll out new kernels and packs safely.  

Every decision (including “random” exploration) produces a **Decision Cell**. On replay, CEP consumes those cells instead of re‑deciding, so the system’s past is not just observable—it is repeatable.  

---

## 2) Technical Details

This section describes the current design: Grounders, Signal Field, Focus Frames, Playbooks, Mode Clusters, and Imaginate, all layered on top of the shipping kernel.  

### 2.0 Layer Overview and Adoption

CEP is organized into five conceptual layers:

1. **Layer 0 – Kernel & Pipeline Substrate**
   Truth substrate (cells/stores/CAS/CPS), heartbeat, async I/O, security, and federation. This is the **only shipping layer** in the kernel repository.  

2. **Layer 1 – Coherence & Pipeline Graphs**
   Beings, bonds, contexts, facets, and pipeline DAGs over them, with runtime records of pipeline runs. Implemented as an optional pack. 

3. **Layer 2 – Ecology & Flows (Modules, Minds & Evolution)**
   Flow VM, species/variants/niches/guardians, scheduler, and the learning vocabulary:
   **Grounders → Signal Field → Focus Frames → Playbooks → Mode Clusters → Imaginate**.  

4. **Layer 3 – Awareness, Datasets & Human Interaction**
   Perspectives, datasets, dashboards, labeling/review tools, and operator panels (human Focus Frames over CEP’s Signal Field).

5. **Layer 4 – Governance, Safety & Self‑Evolution**
   Laws, reforms, councils, provinces, and upgrade pipelines that let CEP evolve its own modules and kernel under supervision. 

**Adoption path**

1. Start with **L0** only as a deterministic kernel and persistence + security substrate.
2. Add **L1** when you need durable identities, relationships, and explicit pipelines.
3. Add **L2** to treat modules as finite‑action learning policies with Playbooks, Focus Frames, and Imaginate.
4. Add **L3** to expose perspectives and datasets to humans.
5. Add **L4** when you want CEP to coordinate its own reforms and upgrades as data.

Layer stacking is one‑way: each layer only depends on lower layers; packs must fail gracefully if their prerequisites are missing.  

---

### 2.1 Core Rhythm: Heartbeats (Capture → Compute → Commit)

The heartbeat is CEP’s metronome:

1. **Capture**

   * Accept new cells and impulses.
   * Freeze the input set for beat *N*.

2. **Compute**

   * Enzymes and episodes read ≤ *N* and stage:

     * branch mutations,
     * policy decisions (Decision Cells),
     * training examples and metrics,
     * parameter updates.

3. **Commit**

   * Atomically promote staged changes to beat *N + 1*.
   * Persist dirty branches via CPS frames.

**Determinism & learning**

* Any non‑deterministic choice (policy pick, RNG draw, variant selection) **must emit a Decision Cell**. 
* Parameter changes are written as new cells that point back to the data and decisions that produced them.
* On replay, CEP **reuses recorded decisions and parameter versions** instead of re‑sampling or re‑training, so past behavior is reproducible even when learning or Imaginate were active. 

Beat evidence lives under `/rt/**` and `/journal/**` when enabled. 

---

### 2.2 Layer 0 – Kernel & Pipeline Substrate

Layer 0 is the shipping kernel. It knows nothing about learning or minds; it only knows **cells, stores, operations, and beats**. 

#### 2.2.1 Truth Substrate: Cells, Stores, History

* **Cells**

  * Immutable facts with metadata, optional payloads (`cepData`), and optional child stores.
  * Updates are **append‑only**: you create new cells, you do not mutate old ones.
  * Provenance links in `meta/parents` tie each derived cell to its sources and the code that created it. 

* **Stores & branches**

  * Stores: dictionary, list, tree, hash, packed queue, octree, etc.
  * Branches: rooted under `/data/<branch>` with their own CPS policies and metrics.  

* **Persistence & CAS**

  * CPS writes beat‑scoped flat frames to storage using a flat serializer with CRC32C + Merkle root; large payloads go to `/cas/**`. 
  * Branch metrics and policies live under `/data/persist/<branch>/**`. 

Cells are the only way to represent truth. Focus Frames, Signal Fields, Playbooks, and mode statistics later in L2/L3 are all just structured arrangements of cells.

#### 2.2.2 Enzymes, Episodes, and Kernel Organs

* **Enzymes**

  * Registered descriptors under `/enzymes/**` specify callbacks, match policies, dependencies, and idempotency hints.
  * Cell bindings attach enzymes to subtrees; tombstones mask inheritance to keep dispatch deterministic. 

* **Episodes (E3)**

  * Long‑running work (training jobs, upgrade pipelines) appears as `op/ep` dossiers under `/rt/ops/**`.
  * Episodes run slices with CPU/IO budgets and can yield/await across many beats. 

* **Kernel organs (structural)**

  * “Organs” in L0 are **typed subtrees with validator/ctor/dtor(/etc) enzymes**, registered under `/sys/organs/<kind>/spec`. 
  * They define the structure of branches like `/data/coh`, `/data/flow`, `/data/eco`, etc.

#### 2.2.3 Async I/O, Persistence, Replay

* **Async fabric**

  * I/O requests are tracked under `/rt/ops/op/io/**` and completed via a reactor.
  * Completions only become visible in Compute, keeping order deterministic. 

* **CPS**

  * `cps_storage_commit_current_beat()` serializes dirty branches to flat frames, hands them to a storage engine, and records metrics + CEI (`persist.*`) events. 

* **Replay**

  * Any beat range can be re‑run with side effects disabled; Decision Cells and CPS logs ensure the re‑run is byte‑for‑byte identical to the original. 

#### 2.2.4 Federation, Security, Pipeline Substrate

* **Federation**

  * Transport providers register capabilities under `/net/transports/**`; mounts and peers live under `/net/mounts/**` and `/net/peers/**`.  

* **Security / enclaves**

  * `/sys/security/**` defines enclaves, edges, gateways, and branch policies; a resolver enforces budgets and emits CEI (`sec.edge.deny`, `sec.limit.hit`, `sec.pipeline.reject`). 

* **Pipeline substrate**

  * L0 threads pipeline metadata (`pipeline_id`, `stage_id`, optional `dag_run_id`, `hop_index`) through envelopes, CEI origin, OPS dossiers, and federation requests, without interpreting the graph. 
  * Higher layers use this to tie decisions and metrics back to logical pipelines.

---

### 2.3 Layer 1 – Coherence & Pipeline Graphs

Layer 1 turns the kernel’s raw branches into **structured entities and pipelines**. It is implemented today as an optional pack that builds on L0 organs and APIs. 

#### 2.3.1 Beings, Bonds, Contexts, Facets

* **Beings** – durable identities: users, documents, services, models, datasets, pipelines, provinces.
* **Bonds** – typed relationships between beings: “owns”, “depends_on”, “in_province”, etc.
* **Contexts** – N‑ary relations that tie multiple beings into a situation (e.g. `(user, model, dataset, environment)`).
* **Facets** – smaller truths implied by contexts; L1 enforces closure or records “debts” if required facets are missing.  

These live under `/data/coh/**` with adjacency mirrors for fast neighborhood queries.

#### 2.3.2 Pipelines as Graphs

Pipelines become first‑class objects:

* Pipeline beings and stage beings with owners and province membership.
* Pipeline definitions under `/data/flow/pipelines/**` with stages, edges, revisions, and metadata.  
* Edges encoded as contexts (`pipeline_edge`) with roles (`from_stage`, `to_stage`).

L1 also maintains **runtime runs** under `/data/flow/runtime/runs/**`, echoing pipeline and stage structure plus per‑stage metrics and annotations.

#### 2.3.3 From Structure to Execution

Given coherence and pipeline definitions:

* L1 decides when pipeline stages are **ready** (events, labels, or schedules).
* It emits L0 operations and OPS dossiers tagged with `pipeline_id` and `stage_id`, which drive enzymes, episodes, and (later) L2 flows. 

L1 does **not** define learning or imagination; it simply defines **who and where** work will run.

---

### 2.4 Layer 2 – Ecology & Flows (Modules, Minds & Evolution)

Layer 2 is where CEP’s **learning and cognition metaphor** lives: flows, Grounders, Signal Field, Focus Frames, Playbooks, Mode Clusters, and Imaginate. It is scaffolded today as an optional pack on top of L1.  

#### 2.4.1 Flow VM and Ecology

The Flow VM is unchanged in spirit:

* Nodes: **Guard / Transform / Wait / Decide / Clamp**.
* Flows: graphs of nodes under `/data/eco/flows/<flow>/graph`.
* Scheduler: `cep_l2_runtime_scheduler_pump()` steps “organisms” (flow instances) each beat with budgets. 

Ecology concepts:

* **Species** – families of flows tackling the same task.
* **Variants** – concrete implementations or parameterizations of a species.
* **Niches** – contextual regions where certain variants are preferred.
* **Organisms** – runtime instances of flows bound to pipeline contexts.
* **Guardians** – constraints that veto unsafe moves or clamp budgets.  

Metrics and history live under `/data/eco/metrics/**`, `/data/eco/runtime/{organisms,history,decisions}/**`. 

#### 2.4.2 Grounders and the Signal Field

To connect CEP’s minds to the external world, L2 introduces **Grounders**:

* A **Grounder** is a module that *grounds CEP in reality*:

  * It attaches to `/env/**` handles (UI, network, devices, files, streams). 
  * It can be a **sensing grounder** (input), **acting grounder** (output), or both.
  * It is implemented as a Flow + L0 organs, but conceptually we treat it as a single I/O agent.

Grounders emit **metrics** (latency, error rate, user confusion, load, etc.) and CEI facts. 

A dedicated L2 flow aggregates these into the **Signal Field**:

```text
/data/eco/runtime/signal_field/current = {
    fast:          0.2,
    precise:       0.8,
    low_noise:     0.9,
    teach:         0.0,
    visual_strain: 0.4,
    ...
}
```

* Keys – active broadcast cues (finite vocabulary; e.g. `fast`, `precise`, `round_up`, `teach`, `low_noise`).
* Values – continuous intensities per signal for richer decisions (typically 0–1; `0` or absence can be treated as “off”).
* Provenance (which Grounder contributed to which signal) is tracked via cell metadata or a sibling branch such as `/data/eco/runtime/signal_field/sources/**`.

This **Signal Field** is the shared “how things feel right now” state that all learners can read.

#### 2.4.3 Focus Frames, Playbooks, Mode Clusters

On top of the Signal Field, L2 defines how individual learners think:

* **Focus Frame**

  * A small, explicit **peephole** over system state:

    * a slice of the Signal Field,
    * plus local hints (e.g. token features in calc, layout stats in UI, cohort flags in ranking),
    * and optional mode labels.
  * Each learner constructs its own Focus Frame for each decision.

* **Playbook**

  * For each Focus Frame signature (a hashed/bucketed form), a Playbook row tracks:

    ```text
    actions: [
      { id: A, attempts, successes, avg_cost },
      { id: B, attempts, successes, avg_cost },
      ...
    ],
    imaginate_state: { ... }
    ```
  * The **Decide** node:

    * looks up the row for the current Focus Frame,
    * picks an action from a finite set,
    * emits a Decision Cell with the Focus Frame signature and action ID. 

* **Mode Clusters**

  * CEP clusters time‑series of `{Signal Field, active flows/guardians, CEI topics}` into recurrent **Mode Clusters** – stable patterns of behavior (e.g. “Overprotective Guardian”, “Aggressive Explorer”).
  * A light L2 analytics flow labels beats with their closest Mode Cluster and records that in the Signal Field.
  * Learners can include `mode_id` in their Focus Frame, making their behavior aware of these attractors.

Together, these define a **Mind Loop**:

> Grounders → Signal Field → Focus Frame → Playbook → Decision → Feedback → Playbook update.

The **peephole constraint** is deliberate: no learner sees the entire state; each sees only what’s encoded in its Focus Frame, which is itself derived from the Signal Field (grounder consensus) and local context.

#### 2.4.4 Imaginate: Structured Imagination & Exploration

To support **imagination**, L2 adds a structured exploration mode: **Imaginate**.

* **Imaginate mode**

  * For a given Focus Frame, instead of always taking the top‑ranked action, a learner can **sample** from its Playbook row:

    ```text
    p(action) ∝ f(success_rate, 1/avg_cost, exploration_bias)
    ```
  * The sampling is deterministic w.r.t. Decision Cells:

    * the sampled rank or RNG seed is stored in the Decision Cell,
    * replay uses the recorded choice; no re‑sampling.  

* **When Imaginate is allowed**

  * L2 reads the Signal Field’s signals (e.g. `teach`, `low_noise`, a dedicated `imagine` cue).
  * L4 laws and guardians decide where and when imaginate is permitted (e.g. shadow provinces, low‑risk users, non‑critical pipelines). 

* **Learning from imagination**

  * After the system observes the outcome (success/failure, cost, or human feedback):

    * the learner updates `attempts`, `successes`, `avg_cost`, and `imaginate_state` for that action in its Playbook row;
    * guardians feed strong negative signals back into the Signal Field if imaginate caused violations (`eco.guardian.violation`, `eco.limit.hit`). 

* **Cooperative imagination**

  * Because Playbooks are conditioned on the shared Signal Field, multiple learners can enter imaginate mode **coherently**:

    * a calc learner trying a new parse path,
    * a layout learner trying a new template,
    * a ranking learner trying a different diversity strategy,
    * all under the same “system mood” encoded in signals like `teach + low_noise`. 

Imagination is always:

* bounded to **finite action sets**,
* recorded as Decision Cells,
* wrapped in **Clamp** nodes and guardians,
* and governed by L4 laws about where it may run.

#### 2.4.5 Modules as Finite‑Action Policies with Supervision

From a learning perspective, a module in L2 is:

* a **Flow** that:

  * builds a Focus Frame from the Signal Field + context,
  * looks up a Playbook row,
  * picks an action (deterministic or imaginate),
  * logs a Decision Cell,
  * runs the chosen path, and logs feedback. 

Supervision comes from:

* labels, rewards, and metrics,
* teach‑me requests when local history is insufficient,
* and human feedback captured at L3.

Directors and trainers are themselves flows with their own Playbooks; their decisions are subject to the same determinism and governance.

---

### 2.5 Layer 3 – Awareness, Datasets & Human Interaction

Layer 3 turns CEP’s internal evidence into **views, tools, and stories** for humans. It builds on the same primitives (Signal Field, Focus Frames, Playbooks), but for operators rather than modules. 

#### 2.5.1 Perspectives, Summaries, Mode‑Aware Views

* **Perspectives**

  * Materialized views over:

    * decisions and Playbook distributions,
    * performance and fairness metrics,
    * Signal Field history,
    * Mode Cluster occupancy (“how often we’re in which mode”).

* **Summaries**

  * Aggregations over time (beats → minutes → hours → days) with links back to Decision Cells and raw evidence.

* **Operator Panels (human Focus Frames)**

  * L3 defines **operator panels**: curated Focus Frames for humans:

    * a small subset of signals,
    * selected metrics and modes,
    * relevant pipelines and species.
  * Panels deliberately **do not show everything**; they enforce the same “peephole” discipline humans use to stay sane while supervising a complex system.

All of these live as cells under `/data/awareness/**` or pack‑specific branches.

#### 2.5.2 Human‑Facing Tools

Typical tools in L3:

* **Dashboards & analytics** – show health, mode usage, Signal Field trends, and Playbook coverage.
* **Dataset & decision browsers** – let humans inspect examples, decisions, and feedback with full provenance.
* **Labeling & feedback UIs** – support human‑in‑the‑loop labels and corrections.
* **Override & triage controls** – let humans:

  * disable or down‑weight variants,
  * change Imaginate policies,
  * or move pipelines between provinces.

Humans thus act as high‑level directors and guardians, using evidence produced by the Mind Layer instead of magic.

---

### 2.6 Layer 4 – Governance, Safety & Self‑Evolution

Layer 4 encodes how CEP, its modules, and even its kernel are allowed to **change**. It uses the same evidence (cells, CEI, perspectives) to drive **laws and reforms**.  

#### 2.6.1 Laws, Reforms, Councils, Provinces

* **Laws**

  * Signed bundles describing:

    * allowed pipelines and flows,
    * safety constraints and budgets,
    * where Imaginate is allowed,
    * privacy and fairness boundaries,
    * upgrade constraints.

* **Reforms**

  * Structured change plans:

    * “promote variant X”,
    * “tighten clamps on species Y in province Z”,
    * “enable a new pack, grounder, or flow.”
  * Include pre‑checks, monitoring conditions, and rollback rules.

* **Councils**

  * Human + automated members who:

    * propose laws and reforms,
    * review L3 evidence,
    * approve or reject changes.

* **Provinces**

  * Named deployment sandboxes (`prod`, `staging`, `shadow`, `experimental`) with their own law sets and ecosystems. 

Laws can also constrain **how wide** operator panels and internal Focus Frames may be (maximum number of panic zones, CEI topics per beat, etc.), treating “how much you can see at once” as a governed resource.

#### 2.6.2 Self‑Evolution and Kernel Upgrades

CEP treats its own source, builds, and binaries as artifacts:

* L4 can define **upgrade pipelines** that:

  * build new kernels or packs,
  * test them in separate provinces,
  * collect L3 metrics and human review,
  * roll them out gradually if councils approve. 

These pipelines themselves are:

* flows with **Decision Cells**,
* subject to laws and guardians,
* and fully replayable for audits.

CEP never mutates its own C code spontaneously; all self‑evolution goes through explicit artifacts, laws, and human oversight.

---

### 2.7 Observability, Privacy, and Replay

Observability is not an add‑on; it is built into the cell model. 

* Every derived cell links to:

  * its parent facts,
  * the enzyme/flow/species that wrote it,
  * the Decision Cells it depends on.

* OPS dossiers under `/rt/ops/**` record:

  * boot/shutdown,
  * persistence and async I/O,
  * pack‑defined operations and episodes. 

* CEI (Common Error Interface) facts:

  * carry severity (`sev:*`), topic, note, origin, and attachments,
  * are used by all layers to report anomalies and limit hits. 

**Privacy**

* Payload‑level cryptography with per‑subject keys:

  * encrypted payloads with `secmeta` describing mode, key ID, nonce, and codec,
  * erasure by dropping keys while keeping structural stubs,
  * optional redaction cells for reversible masking. 

**Replay**

* Beat‑scoped CPS logs + Decision Cells allow any interval to be replayed deterministically, with side effects disabled.
* Learning, Imaginate, and even upgrades are just cells and decisions; replay makes them inspectable.  

---

### 2.8 Scale and Federation

CEP scales by **sharding** work into branches and runtimes, then coordinating them via federation rather than global barriers. 

* Each runtime:

  * owns its own `/data/**` branches, heartbeat, and CPS engine,
  * maintains its own Grounders, Signal Field, Playbooks, and Mode Clusters.

* Federation:

  * uses transports and mounts under `/net/**` to exchange **flat frames and summaries**, not shared memory,
  * carries pipeline metadata and respects enclave policies and budgets.  

Across many runtimes, you get:

* local **minds** with their own Focus Frames and Imaginate behavior,
* a **societal layer** (L3/L4) that aggregates summaries, mode statistics, and upgrade decisions across provinces and peers, without any single node needing to see everything at once.

---

### 2.9 Minimal Viable CEP (Revised Stack)

You can adopt CEP incrementally:

1. **L0 – Kernel & Pipeline Substrate**

   * Heartbeat, cells/stores, CPS/CAS, security, federation, pipeline metadata.

2. **L1 – Coherence & Pipeline Graphs**

   * Beings, bonds, contexts, facets, pipeline graphs and runtime runs.

3. **L2 – Ecology & Flows (Modules, Minds & Evolution)**

   * Flow VM + scheduler, species/variants/niches/guardians, Grounders, Signal Field, Focus Frames, Playbooks, Mode Clusters, Imaginate.

4. **L3 – Awareness & Human Interaction**

   * Perspectives, datasets, operator panels, labeling/feedback tools, override controls.

5. **L4 – Governance & Self‑Evolution**

   * Laws, reforms, councils, provinces, upgrade pipelines.

At each step, the kernel guarantees determinism and replay; higher layers add structure, learning, and governance without weakening that guarantee. 

---

### 2.10 Worked Example: Imaginative Feed Ranking with Human Oversight

Consider a feed ranking system with supervised learning and imagination.

#### Beat 1 – Capture: view event

```text
Event#view1 { user=alice, items=[i1, i2, i3], context=home_feed }
```

* L0 records this under `/data/app/events/**` with `pipeline_id=learn/feed_ranking`. 

#### Layer 1 – Coherence & Pipeline Graph

* Beings: `user:alice`, `model:feed_ranking`, `dataset:home_feed`, `pipeline:FeedRanking`.
* Context ties them; pipeline `FeedRanking` defines stages:

  1. `PrepareFeatures`
  2. `ScoreItems`
  3. `LogExample`
  4. `AwaitLabel`
  5. `ApplyUpdate` 

L1 routes `Event#view1` into stage `PrepareFeatures` and emits an L0 op with metadata.

#### Layer 2 – Grounders and Signal Field

* A **grounder** for user activity reads the event stream under `/env/ui` and `/data/app/events/**`, producing metrics like request latency, click errors, and UI load. 
* Another grounder tracks storage health and model load latency.

The Signal Aggregator flow combines these into:

```text
Signal Field:
  { precise: 0.8, low_noise: 0.7 }
```

So the system is in a cautious, accurate mode with moderate stability.

#### Layer 2 – Focus Frame, Playbook, and Decision

For this request, the ranking learner:

1. Builds a **Focus Frame**:

   ```text
   signal_slice = { precise, low_noise }
   local_view   = { cohort: "new_user", list_len: 3 }
   mode_id      = "NormalOperation"
   ```

2. Computes a Focus Frame signature key.

3. Looks up its **Playbook row**:

   ```text
   key: (precise+low_noise, new_user, len=3)

   actions:
     - A: { id: "Ranker_v1", attempts: 1200, successes: 0.98, avg_cost: 3.0ms }
     - B: { id: "Ranker_v2", attempts:  300, successes: 0.97, avg_cost: 2.1ms }
   imaginate_state:
     exploration_bias: small
   ```

4. Since there is no `teach`/`imagine` signal and the province is `prod`, guardians forbid Imaginate; the Decide node picks **A** deterministically.

5. A Decision Cell records:

   * Focus Frame signature,
   * chosen action A,
   * pipeline/species/variant/niche identifiers. 

The ranking flow scores items with `Ranker_v1`, emits scores and a training example cell referencing the Decision Cell.

#### Beat 3 – Capture: click label arrives

```text
Event#click1 { user=alice, item=i2, label=clicked, context=home_feed }
```

L1 joins this label to the earlier example; L2’s training flow:

* computes a loss,
* emits a parameter update cell under `/data/learn/models/feed_ranking/**`,
* logs another Decision Cell if any randomness (e.g. learning rate choice) was used.  

#### Later – Imaginate trial in an experimental province

A council approves a **reform**: allow imaginate trials for `Ranker_v2` in `experimental` province for new users when the Signal Field indicates high stability (`low_noise` high, no recent `eco.guardian.violation`). 

For a similar context in `experimental`:

1. Signal Field: `signals = ["teach", "low_noise"]`.
2. Focus Frame signature matches the same `(new_user, len=3)` bucket, but now with `teach`.
3. The Playbook’s imaginate policy activates:

   * sample between `Ranker_v1` and `Ranker_v2`, biased toward `Ranker_v2`.
4. Suppose `Ranker_v2` is sampled:

   * Decision Cell marks `mode=imaginate`, sample rank, and Focus Frame signature.
   * The flow serves results and logs feedback after seeing clicks.

If performance is good and guardians stay quiet:

* `Ranker_v2`’s success stats improve,
* the imaginate policy gradually promotes it,
* L4 may later roll out a reform to make `Ranker_v2` the default in more provinces.

This entire evolution—grounder metrics, Signal Field shifts, Focus Frames, decisions, and reforms—is just cells and Decision Cells, so it can be replayed and audited.

---

### 2.11 Glossary

**Kernel & Substrate**

* **Cell** – Immutable fact with metadata, payload, and optional child stores.
* **Store** – Data structure for children (dictionary, list, tree, hash, octree, etc.).
* **Branch** – Rooted subtree under `/data/<name>` with its own persistence policy.
* **Enzyme** – Deterministic callback bound to trees of cells.
* **Episode (`op/ep`)** – Long‑running operation tracked across beats.
* **Heartbeat** – Capture → Compute → Commit rhythm.

**Coherence & Pipelines**

* **Being** – Long‑lived identity (user, model, dataset, pipeline, province).
* **Bond** – Typed relation between beings.
* **Context** – N‑ary relation tying beings into a situation.
* **Facet** – Smaller truth implied by a context.
* **Pipeline** – Graph of stages and edges over beings and contexts.
* **Stage** – Step in a pipeline bound to an enzyme or flow.

**Ecology, Minds & Learning**

* **Species** – Family of flows/modules solving the same task.

* **Variant** – Concrete implementation/parameterization of a species.

* **Niche** – Context region where certain variants are preferred.

* **Organism** – Runtime instance of a flow/module in a specific context.

* **Guardian** – Safety gate enforcing invariants and budgets.

* **Flow** – Deterministic state machine built from Guard/Transform/Wait/Decide/Clamp nodes.

* **Decision Cell** – Recorded choice for any non‑deterministic action.

* **Grounder** – L2 module that anchors CEP to external resources (I/O, UI, devices) via `/env/**`, emitting metrics and CEI.

* **Signal Field** – Compact global state of “how the system is doing” derived from grounder metrics and CEI; represented as a small set of signals and numeric intensities.

* **Focus Frame** – Small, explicit peephole over the Signal Field + local hints + optional mode label; the input each learner uses to decide.

* **Playbook** – Per‑Focus‑Frame table that maps to a finite set of actions, tracking attempts, successes, and cost statistics, plus Imaginate state.

* **Mode Cluster** – Recurrent pattern in `{Signal Field, active flows/guardians, CEI topics}`; behaves like an attractor or “system mood” that learners can condition on.

* **Mind Loop** – The end‑to‑end loop: Grounders → Signal Field → Focus Frame → Playbook → Decision → Feedback → Playbook update.

* **Imaginate** – Structured exploration mode where learners sample from Playbook actions guided by statistics; every sampled choice is logged in a Decision Cell and enforced by guardians/clamps.

**Awareness & Governance**

* **Perspective** – Materialized view over runs, metrics, decisions, and data.
* **Summary** – Aggregated metrics over time frames.
* **Operator Panel** – Human‑facing Focus Frame: a curated slice of Signal Field, modes, metrics, and pipelines.
* **Law** – Signed, versioned bundle of schemas and policies.
* **Reform** – Structured change plan (rollout/rollback) for laws, pipelines, and modules.
* **Council** – Group/process that reviews evidence and approves reforms.
* **Province** – Namespaced environment (prod/staging/shadow/experimental) with its own laws and pipelines.

With these concepts, CEP is not just a kernel with learning bolted on: it is a **deterministic, observable, and governable mind platform**, where every piece of “thinking” is encoded as cells, flows, and small tables that you can inspect, replay, and evolve.

---

### 2.12 Q/A

**Q: Is CEP an ML platform, a database, or an orchestrator?**
CEP is a **deterministic runtime** with storage and orchestration *built in*, and learning layered on top. Layer 0 behaves like a small database + scheduler (cells, branches, CPS, async I/O, federation).  Layers 1–2 add pipelines, flows, and learning (Playbooks, Focus Frames, Imaginate).  Layers 3–4 add awareness and governance. It is not “just” any one of these; it’s a stack that treats all three as first‑class.

**Q: What actually ships today, and what is still design?**
Only **Layer 0 – Kernel & Pipeline Substrate** ships in this repo today: heartbeat, cells/stores, CPS/CAS, security, federation, and pipeline metadata plumbing.  Layers 1–2 have partial scaffolding (coherence, flow VM, ecology roots), and Layers 3–4 are design + contracts that shape how Layer 0 behaves and exposes APIs. 

**Q: Do I need all layers to get value?**
No. Common paths:

* Use **L0 only** as a deterministic kernel and storage substrate. 
* Add **L1** when you need explicit pipelines and long‑lived identities. 
* Add **L2** when you want modules that learn via Playbooks and Signal Fields. 
* Add **L3–L4** only when you care about rich human supervision, laws, and upgrade pipelines. 

Each pack must fail gracefully if absent; Layer 0 boot and replay never depend on them. 

**Q: What is a “mind” in CEP terms?**
A “mind” is not a special object; it’s a pattern:

> Grounders → Signal Field → Focus Frames → Playbooks → Decisions → Feedback.

Any set of flows that read the same slice of **Signal Field**, build similar **Focus Frames**, and maintain **Playbooks** over those can be treated as a “mind loop.” Mode Clusters describe the stable patterns those loops fall into. 

**Q: How is this different from a normal RL/ML system?**
CEP’s default pattern is:

* **Tabular, finite actions per context** (Playbooks),
* **Immediate feedback** (no long credit assignment),
* **Deterministic replay** via Decision Cells,
* **Small, composable modules** instead of monolithic models. 

You *can* host model‑backed policies in flows, but the core story is “tiny supervised learners with explicit tables and policies, glued together by CEP,” not “one giant opaque model.”

**Q: How can CEP both learn and stay deterministic?**
Because every non‑deterministic choice emits a **Decision Cell**, and every parameter update is a new cell tied to those decisions. 

On replay:

* CEP reads the recorded Decision Cells instead of re‑deciding,
* uses the recorded parameter versions,
* and can even replay Imaginate samples because the sampled action/seed is stored with the decision. 

So you get learning *plus* byte‑for‑byte replays.

**Q: What is a Grounder, and how is it different from a kernel “organ”?**

* A **kernel organ** (L0) is a typed subtree descriptor with ctor/validator/dtor enzymes, used to shape branches like `/data/coh`, `/data/flow`, `/data/eco`. 
* A **Grounder** (L2) is a conceptual I/O module that binds to `/env/**` (UI, network, devices) and emits metrics/CEI into the **Signal Field**. 

Internally a Grounder will use one or more organs, but externally we reserve “Grounder” for “thing that touches the world and feeds the Signal Field.”

**Q: Why the “peephole” / Focus Frame instead of just giving learners all the data?**
Two reasons:

1. **Engineering** – Giving every learner the full state would explode Playbook keys and destroy interpretability. Focus Frames enforce a small, explicit input surface. 
2. **Stability** – Both automated learners and humans can “panic” on unfiltered complexity. The peephole makes each mind see only the signals and context it’s designed to handle, and governance can limit how wide those peepholes are. 

**Q: What is “Imaginate” exactly? Is it just random exploration?**
Imaginate is **structured exploration on top of Playbooks**:

* Learners sample from their own action stats instead of always picking the top option.
* Sampling is constrained to finite action sets, governed by policies, and recorded in Decision Cells. 
* Guardians and laws gate where imaginate is allowed (e.g., experimental provinces) and clamp it if it causes limit hits (`eco.guardian.violation`, `eco.limit.hit`). 

It’s not free‑form randomness; it’s “try other rows in the small table, under supervision.”

**Q: How does CEP handle privacy and deletion if everything is append‑only?**
Payloads can be **encrypted per subject**, with metadata (`secmeta`) stored in the cell. Erasure is implemented by dropping keys, leaving structural stubs so history and proofs remain but the sensitive bytes are gone. Optional redaction cells allow reversible masking when appropriate. 

**Q: How does this design relate to the tag lexicon and root layout?**

* The **root layout** (`/sys`, `/rt`, `/journal`, `/env`, `/cas`, `/lib`, `/data`, `/tmp`, `/enzymes`) is fixed by Layer 0 and gives every layer a predictable place to store state and evidence. 
* The **tag lexicon** defines the vocabulary for all of this (`eco`, `learn`, `species`, `variants`, `decisions`, `eco.guardian.violation`, etc.), keeping code and tools in sync. 

Grounders, Signal Fields, Focus Frames, Playbooks, and Mode Clusters are all expressed using that layout and tag vocabulary; they don’t introduce ad‑hoc paths.
