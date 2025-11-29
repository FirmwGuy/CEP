# 🌱 Cascade Evolutionary Processing (CEP)

CEP is a **living, evolving platform for deterministic work, supervised learning, and self‑modifying systems**: it remembers every fact, lets you try new tactics safely, and explains why things changed over time.

If you imagine a system that:

* runs on a steady heartbeat,
* remembers *why* it did things, not just *what* it did,
* and can slowly teach its own modules better habits,

you’re in the right mental place.

> **Status:** Active research project. Layer 0 (the kernel) is shipping; higher layers and learning patterns are in various stages of design and prototyping.   

---

## ✨ Why CEP?

Most stacks force an uncomfortable trade‑off:

* **Hard guarantees, soft intelligence**
  Strong control, simple workflows, but little room to adapt.

* **Flexible learning, fuzzy accountability**
  Lots of experimentation, but “why did this happen?” is hard to answer.

CEP’s goal is to be a **spine** you can trust in both directions:

* **Deterministic history**
  Facts are immutable cells; every derived fact points back to its inputs and the code that produced it. You can replay a time range and get the same answers again. 

* **Structured learning**
  Modules don’t improvise freely; each one has a small menu of allowed actions and a tiny table of “what usually works here.” Those tables are updated based on feedback. 

* **Governed change**
  Pipelines, policies, and (eventually) CEP’s own upgrades move through laws, reforms, and councils—not silent hotfixes. 

The aim is that a product owner, operator, or regulator can ask:

> “What did we do, why, and what did we learn from it?”

…and get a **concrete, replayable story**, not just a dashboard snapshot.

---

## 🧬 How CEP runs (Capture → Compute → Commit)

CEP runs on a strict heartbeat:

1. **Capture**
   CEP freezes the new inputs for beat *N*:

   > “User clicked Save”, “We got a webhook”, “A learner chose option B”.

   Once Capture ends, the input set for that beat is fixed. 

2. **Compute**
   The kernel wakes the relevant work:

   * **enzymes** (small deterministic callbacks),
   * **episodes** (longer‑running operations),
   * and, when packs are present, **flows** and learning modules.

   They read only data that’s valid up to beat *N*, stage changes, and log any non‑deterministic decisions into **Decision Cells** for replay.  

3. **Commit**
   CEP atomically publishes all staged changes as beat *N + 1* and hands dirty branches to the persistence service (CPS) to serialize them. Once committed, history is append‑only. 

Key properties:

* **No half‑seen state**: observers only see fully committed beats. 
* **Replayable**: re-running a beat range with external side effects disabled produces the same decisions and outcomes, because Decision Cells are consumed instead of re‑deciding. 
* **Composable**: all upper layers (pipelines, flows, learning, governance) are “just” patterns over this heartbeat and the cell store.

---

## 🏗 Layers in plain language

The project is structured as five layers. Only **Layer 0** is a hard requirement; everything else is designed as an optional pack on top.  

| Layer                                           | Feels like…                                              | Why you care                                                                                                                             |
| ----------------------------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **L0 – Kernel & Pipeline Substrate**            | A tiny OS for facts and time.                            | Heartbeat, cells/stores, persistence (CPS), async I/O, security, federation, and pipeline metadata plumbing. This is what ships today.   |
| **L1 – Coherence & Pipeline Graphs**            | A map of “who/what/where” that stays consistent.         | Beings/bonds/contexts/facets, plus pipelines as graphs with runs, triggers, and basic metrics.                                           |
| **L2 – Ecology & Flows (Learning & Evolution)** | An ecosystem of tactics trying jobs in different niches. | Flow VM (Guard/Transform/Wait/Decide/Clamp), species/variants/niches/guardians, and tabular learning loops.                              |
| **L3 – Awareness & Human Interaction**          | Dashboards and dataset views that know the context.      | Perspectives, summaries, labeling tools, operator panels, override controls.                                                             |
| **L4 – Governance, Safety & Self‑Evolution**    | Councils, laws, provinces, and upgrade stories.          | Governs what’s allowed to change, how it rolls out, and how CEP may upgrade itself.                                                      |

**Adoption path**

* Start with **L0** as: deterministic data engine + heartbeat.
* Add **L1** when you want explicit pipelines and coherent identities. 
* Add **L2** when you want finite‑action learners and variant experiments.  
* Add **L3/L4** once you need operator dashboards, approvals, and upgrade pipelines.

Layer stacking is strictly one‑way: L1 uses L0; L2 uses L1+L0; higher layers never bypass lower ones. 

---

## 🧠 Learning & “minds” (in simple terms)

CEP’s learning story is deliberately small and explicit. Instead of one giant model, you get many tiny, supervised “mini‑brains”:

* **Grounders**
  Modules that touch the world via `/env/**` (UI, network, devices, files). They emit metrics and error facts (CEI), which tell CEP “how things are going” right now.  

* **Signal Field**
  A compact summary such as:

  > “We’re under latency pressure”, “noise is low”, “user asked to be taught”.

  It’s built from Grounder metrics and CEI topics—similar to the “selective environmental signals” used in the current learning approach. 

* **Focus Frames**
  Each learner sees only a small **peephole**:

  * a slice of the Signal Field,
  * a few local hints (like “short query” or “new user”),
  * and maybe a “mode” label (a behavioral cluster the system has discovered).

* **Playbooks**
  For each type of Focus Frame, a module keeps a **tiny table** of allowed actions and statistics:

  > In this situation, which actions did we try? How often did they work? How expensive were they?

* **Imaginate**
  When rules allow it, a learner can **sample** from its own Playbook row instead of always taking the top choice—trying alternates in low‑risk contexts. Every such choice is logged as a Decision Cell for replay. 

The loop looks like this:

> Grounders → Signal Field → Focus Frame → Playbook → Decision (maybe Imaginate) → Feedback → Playbook update.

All the tables and decisions live under `/data/eco/**` and `/data/learn/**` as normal CEP data.  

---

## 🛠 What you can do (even without hacking the kernel)

You don’t need to touch C to work with CEP’s ideas. A few common roles:

1. **Model and data owners**

   * Treat CEP as a traceable host for your models and policies.
   * Log predictions, labels, and outcomes as cells.
   * Use Playbook‑style learners to manage safe exploration. 

2. **Policy / compliance / governance teams**

   * Represent policies as data (laws, reforms, provinces), not just wiki pages. 
   * Ask for replayable evidence when something goes wrong.

3. **Product and operations**

   * Design pipelines as graphs instead of strings of ad‑hoc calls. 
   * Run multiple variants safely, promote the ones that win, and retire the ones that don’t.

4. **Tooling & platform engineers**

   * Map CEP’s cells and CEI into your own tools (search, dashboards, alerting).
   * Use the Tag Lexicon to stay aligned with CEP’s vocabulary. 

Because everything is append‑only and replayable, many workflows feel more like editing a **ledger of behavior** than patching a black‑box service.

---

## 🚀 Example use cases

Here are a few ways CEP’s design fits into real systems.

### 1. Auditable A/B(/n) pipelines

* Treat each strategy or model as a **variant** in L2. 
* Use L1 to define the pipeline stages for “prepare → decide → log → label → update.”
* Each variant choice is a Decision Cell with pipeline metadata; replays can reconstruct what any user saw and why. 

### 2. Safer ML rollouts

* Use **provinces** (prod, staging, experimental) in L4 to keep risky variants in the right places. 
* Let L3 dashboards show coverage, error rates, and fairness metrics.
* Advance a variant from experimental to prod via a **reform**, not a manual roll‑out.

### 3. Regulated decision systems

* Use CEP’s deterministic heartbeat and CPS persistence as an **audit backbone** for decisions. 
* Represent policy changes and approvals as cells and CEI facts.
* When asked “why was X denied/approved?”, replay the relevant beats instead of relying on reconstructed logs.

### 4. Multi‑team product platforms

* Each team runs its own pipelines and learners, but they share the same kernel and lexicon. 
* Governance defines who can change which pipelines and which provinces they can touch. 

---

## 🔍 Where to dive deeper

The docs are split by “how deep” you want to go:

* **Big‑picture narrative** – `docs/CEP.md`
  Full story of layers, examples, and glossary. 

* **Kernel details** – `docs/CEP-Implementation-Reference.md`
  Heartbeat rules, persistence, OPS, security/federation, and pipeline metadata plumbing. 

* **Contracts & layering** – `docs/CEP-CONTRACTS.md`
  Who owns the heartbeat thread, how optional packs plug in, and what “L1 depends on L0” actually means in code. 

* **Filesystem map** – `docs/CEP-ROOT-DIRECTORY-LAYOUT.md`
  What lives under `/sys`, `/rt`, `/journal`, `/env`, `/cas`, `/lib`, `/data`, `/tmp`, and `/enzymes`. 

* **Vocabulary** – `docs/CEP-TAG-LEXICON.md`
  Canonical tags (like `eco`, `coh`, `flow`, `species`, `variants`, `sec.edge.deny`, etc.) for tools and packs. 

* **Current learning pattern** – `docs/CEP-Learning-Approach.md`
  Calc & layout POCs, tabular learners, broadcast signals, directors/guardians/teachers, and teach‑me escalation.  

---

## 🧭 Current snapshot

Very short version of “what actually exists” today:

* **Shipping: Layer 0 kernel**  

  * Heartbeat (Capture → Compute → Commit)
  * Cells/stores, CAS, CPS persistence
  * Async I/O and OPS timelines
  * Enclave security and federation plumbing
  * Pipeline metadata (`pipeline_id`, `stage_id`, etc.) threaded through OPS, CEI, async, and federation

* **Optional pack: Layer 1 coherence & flow graphs** 

  * `/data/coh/**` (beings, bonds, contexts, facets, debts, adjacency)
  * `/data/flow/**` (pipeline definitions + runtime runs, fan‑in/out, triggers, metrics)

* **Scaffolded pack: Layer 2 ecology & flows** 

  * `/data/eco/**` and `/data/learn/**` roots and organs
  * Flow VM + scheduler, species/variants/niches/guardians
  * Runtime organisms, decisions, metrics, model revisions

* **Design‑stage: Layers 3 & 4** 

  * Awareness: perspectives, datasets, dashboards, operator panels
  * Governance: laws, reforms, councils, provinces, upgrade pipelines

Expect high churn outside the kernel; docs aim to keep you oriented as APIs move.

---

## ❓ Q&A

**Q: Is CEP a database, workflow engine, or ML stack?**
**A:** It’s closer to a **kernel** that can support all three:

* As a database‑like core (cells/stores/CPS) with strict determinism,
* as a workflow engine (enzymes, OPS, pipelines),
* and as a host for learning (flows, species/variants, Playbooks).  

You can use just the parts you need.

---

**Q: How strict is the determinism story really?**
**A:** Quite strict:

* Only the heartbeat thread mutates Layer 0; other work must go through episodes and the executor. 
* Any non‑deterministic choice must emit a Decision Cell. 
* Replays consume those decisions instead of re‑deciding.

If you can’t replay it, CEP treats that as a bug, not a feature.

---

**Q: Where do big neural models fit?**
**A:** CEP doesn’t forbid them, but they’re **not required**:

* Many tasks can be handled with small tabular Playbooks keyed by Focus Frames. 
* If you do use a big model, you typically wrap it as a single action in a Playbook (one of the finite actions) so its usage is still explicit and replayable.

---

**Q: Can CEP really upgrade itself?**
**A:** That’s the **design goal** at L4:

* Treat kernel and pack binaries as just another artifact,
* run upgrade pipelines with tests and metrics,
* gate rollout on councils and laws,
* and record every step as cells and OPS. 

The kernel today is written with that future in mind, but the full self‑evolution loop is still in design/prototype.

---

**Q: Do I need to be a low‑level C or distributed‑systems expert to use CEP?**
**A:** No. The core kernel is written in C for portability and performance, but the **intended users** at higher layers include:

* analysts,
* policy teams,
* product managers,
* and operations staff.

The aim is to expose concepts like **pipelines, variants, councils, and stories** in human language, with the low‑level details hidden behind APIs and tools.

---

**Q: Is CEP production‑ready?**
**A:** Not yet. It’s an **active research project**:

* Layer 0 is maturing but still evolving,
* higher layers are in design/prototype form,
* documentation and APIs change frequently.

Early adopters should treat it as **experimental infrastructure**, not a drop‑in replacement for a mature database or workflow engine.

---

**Q: Why is determinism such a big deal here?**
**A:** Determinism means:

* If you replay the same inputs and recorded decisions, you get the **same outputs**.
* This is essential for:

  * audits,
  * debugging,
  * regulatory explanations,
  * and understanding how learning systems changed over time. 

Without determinism, it’s very hard to answer “why did this happen?” with confidence.

---

## 📝 Licensing

CEP ships under the **Mozilla Public License 2.0** (see `NOTICE` and `docs/LICENSING.md`) so kernel improvements remain share‑alike while still allowing proprietary packs to stay separate.

**Why not MIT licensed?**
MIT would let vendors fork the kernel, close their changes, and ship incompatible variants; MPL keeps the core transparent and auditable without blocking teams from building closed workflows on top.
