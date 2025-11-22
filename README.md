# 🌱 Cascade Evolutionary Processing (CEP)

CEP is a **living platform for work**: it remembers every fact, lets you try new tactics safely, and explains why things changed over time.

If you picture a city that:

* keeps its records immaculate,
* lets neighborhoods experiment with new layouts and rules,
* and can replay any day in its history,

you’re very close to what CEP wants to be. 

> **Status:** Active research project; APIs and docs change often. Expect breaking changes.

---

## ✨ Why CEP?

Most systems force a trade‑off:

* **Predictable clocks** – everything is tightly controlled, but nothing adapts.
* **Creative experiments** – lots of exploration, but it’s hard to audit what happened.

CEP refuses that choice. It aims to give you both:

* **Deterministic memory**
  Every change is linked to its causes, so you can **replay, audit, and explain** any decision or outcome later. 

* **Guided evolution**
  Multiple strategies (variants) can try the same job in **safe sandboxes**. Over time, supervisors (human or automated) promote what works and retire what doesn’t. 

* **Human context**
  Rules, reforms, and stories live as first‑class objects, not just log lines. Non‑technical stewards can see *what changed*, *why*, and *what was learned*.

This balance means a product manager, regulator, or operations lead can ask:

> “What happened, why, and what changed next?”

…and get a real, evidence‑backed answer instead of a shrug.

---

## 🧬 How it beats

CEP runs in **heartbeats**: small, repeatable steps that keep the world in sync.

Each heartbeat follows the same **Capture → Compute → Commit** rhythm:  

1. **Capture**
   CEP freezes the new facts for this beat.

   > “Alex clicked Save”, “We received a payment”, “A model proposed option B”.

   Nothing is allowed to slip in or out halfway through; the input for this beat is fixed.

2. **Compute**
   CEP wakes the relevant **enzymes** (small workers) and **flows** (larger procedures) to react:

   * updating records,
   * testing a new variant,
   * logging an experiment,
   * or preparing data for training.

3. **Commit**
   CEP publishes the results and their **provenance** (where they came from, which worker touched them) at the next beat. Once committed, history is never overwritten—only extended.

Because CEP keeps every beat deterministic, you can:

* Rewind to any range of beats.
* Re‑run them in “read‑only mode”.
* Check that the system produces the same decisions again.

No guesswork, no “mystery behavior”.

---

## 🏗 Layers in plain language (matching `CEP.md`)

CEP is defined in **five layers**. Only the first one (L0) is a shipping kernel today; the others are designed as optional packs on top. 

| Layer                                            | What it feels like                                                 | Why it matters                                                                                                                                         |
| ------------------------------------------------ | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **L0 – Kernel & Pipeline Substrate**             | A dependable heartbeat and a tamper‑evident diary of facts.        | Keeps every fact immutable and traceable. Provides storage, deterministic execution, security, and the plumbing for multi‑step pipelines.              |
| **L1 – Coherence & Pipeline Graphs**             | A relationship map that stays in sync automatically.               | If one fact implies another (“this payment belongs to that invoice”), the system records those links and multi‑stage pipelines as first‑class graphs.  |
| **L2 – Ecology & Flows**                         | Multiple tactics try the same job in different “niches”.           | Different variants (models/policies) compete fairly; flows describe how they pick actions, get feedback, and evolve under supervision.                 |
| **L3 – Awareness, Datasets & Human Interaction** | Dashboards and datasets that understand context, not just numbers. | Perspectives, interpretations, and summaries help humans see what’s working, what’s drifting, and where more labels or oversight are needed.           |
| **L4 – Governance, Safety & Self‑Evolution**     | Councils, laws, provinces (prod/staging/experiments), and stories. | Changes roll out with approvals, not surprise patches. The system can even help orchestrate its own upgrades under clear rules.                        |

Today, **L0 is implemented in C** as a portable kernel with a permissive‑friendly license; higher layers are designed to sit on top as ordinary packs and tools. 

---

## 🛠 What you can do (even without code)

You don’t have to be a kernel hacker to play a role. At a high level, CEP encourages this kind of workflow:

1. **Log the truth.**
   Capture facts as they happened. Don’t overwrite; add new entries.

2. **Link related truths.**
   Connect facts that belong together (e.g., “this payment belongs to that invoice”, “this label belongs to that prediction”).

3. **Sponsor variations.**
   Let multiple strategies or models try the same job under controlled conditions. Decide in advance how to compare them.

4. **Review perspectives.**
   Look at dashboards and annotations that explain what’s working, what’s drifting, and where you’re blind.

5. **Promote reforms.**
   When something works, turn it into a rule or a new default, with a **clear rollback plan** if it misbehaves.

6. **Tell the story.**
   Write down the “why”—not just the metrics. Future reviewers should inherit the insight, not just a pile of numbers.

This workflow fits:

* policy & compliance teams,
* product and operations leads,
* analysts and data scientists,
* and storytellers/knowledge managers,

as much as it fits engineers.

---

## 🚀 Potential uses

Here are some concrete ways CEP could be used.

### 1. Transparent A/B (or A/B/n) testing

* Run multiple interface or decision variants at once.
* Guarantee that every choice is logged with context (who, when, which version).
* Later, replay exactly what users saw, how they behaved, and how the system reacted—crucial for audits and post‑mortems.

### 2. Safer machine‑learning rollouts

* Treat models and policies as **variants inside species**, competing in clearly defined niches. 
* Log which model version made which prediction, with inputs, labels, and evaluation metrics.
* Let councils (human supervisors) decide when a new variant is “good enough” to become the default.

### 3. Regulated workflows (finance, healthcare, public sector)

* Use CEP as a **deterministic audit log** that explains:

  * why a decision was made,
  * which policy or model it followed,
  * and how those policies/models changed over time.
* Answer regulators’ questions with replayable evidence instead of hand‑written summaries.

### 4. Multi‑team product platforms

* Different teams can experiment with tactics (pricing, ranking, notifications) without stepping on each other’s toes.
* L4 governance makes it explicit **who is allowed to change what** and under which approvals.
* Provinces (prod, staging, experiments) keep risky changes contained until they earn promotion. 

### 5. Human‑in‑the‑loop supervision

* Use L3 views to surface edge cases, data gaps, or fairness issues.
* Let humans label, re‑label, or veto decisions.
* Feed that feedback into L2 flows as supervised signals, so the system learns from real oversight.

### 6. Self‑evolving infrastructure (long term)

* Because the kernel is written in portable C and licensed under MPL‑2.0, CEP can eventually host **upgrade pipelines** that:

  * build new kernel/pack versions,
  * test them in shadow environments,
  * and, with human approval at L4, roll them out safely. 
* The platform can, in principle, keep a traceable story of its *own* evolution, not just the applications running on top.

These are illustrative, not exhaustive. CEP is intended as a **general substrate** for systems that must both **adapt** and **explain themselves**.

---

## 📚 Where to dive deeper

If you want more detail:

* Start with [`docs/CEP.md`](docs/CEP.md) for the full narrative, glossary, and worked “Save Button” example (how a simple UI action travels through layers). 
* Use [`docs/CEP-Implementation-Reference.md`](docs/CEP-Implementation-Reference.md) when you want the precise deterministic contracts, data structures, and invariants without the storytelling. 
* The orientation map in `docs/DOCS-ORIENTATION-GUIDE.md` tells you which document to open for kernel changes, policy flows, or tooling updates.

---

## 🧭 Current snapshot

Right now, the project is very much in motion:

* **Shipping:**
  **Layer 0 kernel** with deterministic beats, in‑memory stores, persistence, federation hooks, and security policy loading. This is what current code and tests focus on. 

* **Emerging:**
  Early **Layer 1 coherence** (identity & relationships) and **Layer 2 ecology/flow helpers** exist in the tree but evolve frequently. Expect APIs and layouts to change.

* **Planned:**
  **Awareness (L3)** and **Governance/Self‑Evolution (L4)** live primarily in design docs and prototypes. They will arrive as optional packs on top of the kernel once the lower layers finish hardening. 

If you build on CEP today, plan for migrations and breaking changes.

---

## ❓ Q&A

**Q: Is CEP a database, a workflow engine, or an ML platform?**
**A:** CEP is closer to a **kernel for all three**. It gives you:

* a database‑like record of facts (cells),
* a workflow engine (enzymes, episodes, pipelines),
* and a place to host learning logic and policy decisions.

You can plug your own business logic, models, or tools on top.

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

**Q: How does CEP relate to AI / machine learning?**
**A:** CEP is not a model itself. Instead, it’s a **host** for models and decision policies:

* It can log predictions, labels, and outcomes.
* It can orchestrate A/B tests and policy changes.
* It can help you **replay** and **audit** how learning systems evolved and what they did. 

Think of it as the “memory and bones” around your models, not the model brain itself.

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

**Q: Can CEP change itself? That sounds dangerous.**
**A:** Long‑term, yes—**under strict rules**:

* CEP can orchestrate its own upgrades using pipelines and governance rules.
* But those upgrades must:

  * be described explicitly (as reforms),
  * be tied to evidence (tests, metrics),
  * and typically require approval from human councils at L4. 

The goal is **controlled self‑evolution**, not uncontrolled self‑modification.

---

## 📝 Licensing

CEP ships under the **Mozilla Public License 2.0** (see `NOTICE` and `docs/LICENSING.md`) so kernel improvements remain share‑alike while still allowing proprietary packs to stay separate.

**Why not MIT licensed?**
MIT would let vendors fork the kernel, close their changes, and ship incompatible variants; MPL keeps the core transparent and auditable without blocking teams from building closed workflows on top.
