# CEP Learning Approach

CEP’s learning approach is intentionally simple: each module has a small menu of allowed actions, keeps a tiny table of “what worked best in what kind of situation,” and updates those tables as real‑world feedback arrives. A shared **Signal Field** summarizes how the whole runtime is doing, each learner looks through a small **Focus Frame** (its peephole into that state plus local context), and a **Playbook** maps that Focus Frame to a finite set of actions and statistics. Learners can **imaginate** (safely explore alternatives) by sampling from their own Playbook rows, and every choice is written down as a **Decision Cell**, so the whole process stays deterministic and replayable.  

---

## Technical Details

### 1. Goals and constraints

CEP’s learning design is guided by a few hard constraints:

* **Deterministic and replayable**

  * All learning decisions must be reconstructable from history.
  * Any non‑deterministic choice (including exploration) must emit a Decision Cell. 

* **Finite, explicit action sets**

  * Each learner picks from a small, declared set of actions (paths, variants, policies), not an unbounded action space.  

* **Local, tabular learners**

  * No single global model runs everything.
  * Each learner keeps its own small **Playbook**: a table keyed by Focus Frame, with candidate actions and simple stats.

* **Supervised and governed**

  * Learning is driven by labels, rewards, metrics, and human feedback.
  * Guardians, budgets, and security policy constrain when and how learners can explore or change parameters.  

The goal is a system that can adapt and “have ideas” (via Imaginate) without ever becoming opaque or un‑auditably random.

---

### 2. Where learning lives in CEP

CEP is layered; learning lives mostly in the **ecology layer**:

* **Layer 0 – Kernel & Substrate**

  * Heartbeat (Capture → Compute → Commit), cells/stores/CAS/CPS, async I/O, security, federation, OPS, CEI, Decision Cells.  

* **Layer 1 – Coherence & Pipelines**

  * Beings, bonds, contexts, facets; pipeline graphs and runtime runs under `/data/coh/**` and `/data/flow/**`. 

* **Layer 2 – Ecology & Flows**

  * Flows (Guard/Transform/Wait/Decide/Clamp), species/variants/niches/guardians, runtime organisms, metrics, and decision logs under `/data/eco/**` and `/data/learn/**`. 

Learning primitives—Grounders, Signal Field, Focus Frames, Playbooks, Mode Clusters, Imaginate—are Layer 2 concepts built on that scaffolding:

* `eco`, `learn`, `species`, `variants`, `niches`, `guardians`, `flows`, `organisms`, `metrics`, `history`, `decisions` tags are reserved for this layer. 

Layers 3–4 (awareness, governance) consume the evidence from L0–L2 to provide dashboards, override tools, laws, and upgrade pipelines, but they aren’t required for the basic learning loop.

---

### 3. Learning building blocks

#### 3.1 Grounders

A **Grounder** is a learning‑aware module that connects CEP to the outside world:

* Attaches to `/env/**` handles (UI, network, devices, streams). 
* Emits **metrics** (latency, error rates, user confusion, load, etc.) and CEI facts (e.g. `eco.guardian.violation`, `eco.limit.hit`, `sec.limit.hit`).  
* Is implemented as a species/variant/flow in `/data/eco/**`, but conceptually: “this is the thing that feels the world.”

Grounders are the raw sense organs and actuators; they tell the system what is happening “out there.”

#### 3.2 Signal Field

The **Signal Field** summarizes “how the runtime feels right now” in a compact dictionary: one entry per signal. A typical shape:

```text
/data/eco/runtime/signal_field/current = {
  fast:          0.2,
  precise:       0.8,
  low_noise:     0.7,
  teach:         0.0,
  visual_strain: 0.4
}
```

* **Keys** – a small vocabulary of broadcast cues (e.g. `fast`, `precise`, `round_up`, `round_down`, `teach`, `low_noise`, `visual_strain`).
* **Values** – numeric intensities (often 0–1); zero or missing can be treated as “off.”

A dedicated L2 flow:

1. Reads Grounder metrics and relevant CEI. 
2. Normalizes and aggregates them into a per‑beat Signal Field.
3. Stores it under `/data/eco/runtime/signal_field/current` (with short history if needed).

Every learner sees the same Signal Field; it’s the shared “climate” of the system.

#### 3.3 Focus Frames (the peephole)

A **Focus Frame** is the small, explicit peephole a learner uses to view the world:

* It includes:

  * a **slice** of the Signal Field (only the signals that matter to this learner),
  * **local hints** (input size, user cohort, stage ID, simple content features),
  * an optional **mode ID** (see Mode Clusters below).

Example:

```text
FocusFrame = {
  signal_slice: { precise: high, low_noise: high },
  local_view:   { cohort: "new_user", list_len: "short" },
  mode_id:      "NormalOperation"
}
```

The learner converts this Focus Frame into a **key** (e.g., a hashed bucket), which indexes its Playbook. This is the “context” for decisions.

#### 3.4 Playbooks

A **Playbook** is a table keyed by Focus Frame, stored per learner:

```text
/data/eco/runtime/playbooks/<learner>/<focus_key> = {
  actions: [
    { id: "Variant_A", attempts: 1200, successes: 0.98, avg_cost: 3.0 },
    { id: "Variant_B", attempts:  300, successes: 0.97, avg_cost: 2.1 }
  ],
  imaginate_state: {
    exploration_bias: 0.1,
    last_sample_rank: 0,
    last_update_bt:   12345
  }
}
```

For each `focus_key`, the table:

* lists the **finite actions** the learner is allowed to choose,
* tracks attempts, successes, and simple costs,
* can store extra fields in `imaginate_state` for exploration policy.

The Flow VM’s **Decide** node:

1. Builds the Focus Frame and its key. 
2. Reads the Playbook row for that key.
3. Picks an action (deterministically or via Imaginate).
4. Emits a **Decision Cell** linking:

   * pipeline/species/variant/niche,
   * Focus Frame key,
   * chosen action,
   * whether Imaginate was used. 

#### 3.5 Mode Clusters

A **Mode Cluster** is a recurrent “shape” of system behavior:

* It is derived from:

  * recent Signal Field samples,
  * active flows/organisms/guardians,
  * CEI topics (e.g. many `eco.guardian.violation` events). 

A small analytics flow:

1. Observes `{signal_field, active_organisms, CEI topics}` per beat.
2. Clusters them into a small set of **modes**, e.g.:

   * `NormalOperation`,
   * `OverprotectiveGuardian`,
   * `AggressiveExplorer`.
3. Writes `mode_id` into the Signal Field (`signal_field/current/mode_id` or a sibling branch).

Learners may include `mode_id` in their Focus Frame, so Playbooks can say things like: “for this Focus Frame, when we’re in OverprotectiveGuardian mode, prefer safer actions.”

#### 3.6 Imaginate (structured imagination)

**Imaginate** is the exploration mechanism:

* Instead of always taking the best‑known action, a learner can **sample** from its Playbook row, based on stats and a configured bias, when exploration is allowed.
* Sampling is always:

  * limited to the finite action set in that Playbook row,
  * recorded in a Decision Cell (including rank/seed),
  * wrapped by guardians and clamps. 

Imaginate is how a learner “imagines” alternative behaviors in a controlled, replayable way.

#### 3.7 Roles around learners

Within this design, several roles emerge:

* **Learner (Trainee)** – a Flow that owns a Playbook and makes decisions based on Focus Frames.
* **Trainer** – a Flow that:

  * aggregates examples and feedback,
  * updates Playbooks or underlying parameters,
  * may adjust Imaginate policies.
* **Guardian** – enforces safety and budgets, vetoing unsafe actions and flagging limit hits.  
* **Director** – examines metrics and coverage and decides:

  * where exploration is allowed,
  * when to promote or retire variants,
  * how strict or adventurous trainers and learners should be.

All of these roles are implemented as normal flows/species in `/data/eco/**`, using the same evidence and primitives.

---

### 4. Local learner loop

The **inner loop** for a learner looks like this:

1. **Observe context and signals**

   * Grounders emit metrics and CEI.
   * The Signal Field is updated for the current beat. 

2. **Build Focus Frame**

   * The learner gathers:

     * its relevant slice of the Signal Field,
     * pipeline and stage metadata,
     * local context features.
   * It turns this into a Focus Frame and a stable key.

3. **Consult Playbook**

   * It locates the Playbook row for that key.
   * If none exists:

     * it may create a new row with a default action set,
     * or escalate via teach‑me if no safe default is known.

4. **Choose an action (Decide)**

   * Normal mode:

     * sort actions by success, then cost; pick the top.
   * Imaginate mode:

     * sample from actions based on stats and exploration bias.
   * Emit a Decision Cell with:

     * Focus Frame key,
     * chosen action,
     * deterministic exploration info.

5. **Execute and log feedback (Transform)**

   * Run the chosen action (e.g. call a variant, apply a policy).
   * Measure outcomes (success/failure, latency, quality metrics).
   * Write feedback cells that point back to the Decision Cell.

6. **Update Playbook**

   * A follow‑up Transform updates attempts/success/cost and ordering for the chosen action in that Playbook row.
   * Some choices may also adjust Imaginate bias (e.g., reduce weight on failures, increase on wins).

Over time, each Focus Frame’s Playbook row converges toward:

* “almost always pick this action,”
* “fall back to this one when conditions change,”
* plus occasional exploration when allowed.

---

### 5. Teach‑me and escalation

Sometimes local tables aren’t enough:

* A Focus Frame appears with no safe action,
* or existing options keep failing,
* or guardians keep vetoing actions for that context.

In those cases, learners can emit a **teach‑me** escalation:

* A cell that includes:

  * the Focus Frame,
  * the current Playbook row,
  * recent decisions and outcomes,
  * reasons for escalation.

Trainer/Director flows:

* review teach‑me cells,
* propose new actions or adjustments (e.g. a new variant for that Focus Frame),
* update Playbooks or parameters accordingly, under Guardian enforcement.

The trainer itself can be treated as a learner with its own Playbooks for:

* when to honor teach‑me,
* how aggressively to adjust Playbooks,
* when to ask humans for help.

---

### 6. Stacking learners

Learners can be **stacked** so decisions cascade:

* A “front” learner makes an interpretive decision (e.g. how to represent an input or which coarse strategy to use).
* A “downstream” learner reads that decision (via the Decision Cell or derived Focus Frame fields) and from there decides on a more specific action.

Pattern:

1. Learner A:

   * Focus Frame A → Playbook A → Decision Cell A.
2. Learner B:

   * Focus Frame B includes “output of A” as part of `local_view`,
   * Playbook B picks a variant conditioned on what A decided.

This ensures ambiguity gets resolved once and then reused; downstream learners don’t guess independently and risk contradictions.

---

### 7. Data placement and tags

The learning data uses existing CEP roots and tags:   

* **Ecology and runtime**

  * `/data/eco/species` – species definitions.
  * `/data/eco/variants` – variant definitions.
  * `/data/eco/niches` – niche definitions.
  * `/data/eco/guardians` – guardian configurations.
  * `/data/eco/flows` – flow graphs.
  * `/data/eco/runtime/organisms` – running learners and Grounders.
  * `/data/eco/runtime/decisions` – Decision Cells for L2 flows.
  * `/data/eco/metrics/{per_species,per_variant,per_niche,global}` – metrics.

* **Signal Field and Playbooks** (convention)

  * `/data/eco/runtime/signal_field/current` – current Signal Field dictionary.
  * `/data/eco/runtime/playbooks/<learner>/<focus_key>` – Playbook rows.
  * `/data/eco/runtime/modes/**` – Mode Cluster definitions and assignments.

* **Models / parameters**

  * `/data/learn/models/**` – model/parameter snapshots.
  * `/data/learn/revisions`, `/data/learn/provenance` – revision index and provenance.  

Each of these is just cells and stores; the learning machinery is expressed entirely in the same data model as everything else.

---

## Q/A

**Q: Is this a full reinforcement learning stack?**
No. The default loop is closer to **contextual bandits**:

* finite actions per Focus Frame,
* immediate feedback,
* no long‑horizon credit assignment by default.

Long‑range strategies can be layered on top by building flows that consider sequences of decisions, but the core is intentionally simple and tabular. 

---

**Q: Where does probability or randomness show up?**
Only inside **Imaginate**, and even there it’s tightly controlled:

* sampling is limited to the actions in one Playbook row,
* every sample is recorded in a Decision Cell (with enough info to replay),
* guardians and laws can restrict where Imaginate is allowed.

If desired, you can run entirely deterministic learning by always picking the top‑ranked action and disabling Imaginate.

---

**Q: How can the system both explore and stay deterministic?**
Determinism comes from **Decision Cells** and the heartbeat: 

* Every non‑deterministic choice (including Imaginate) writes down:

  * pipeline/species/variant/niche,
  * Focus Frame key,
  * chosen action,
  * any sampling rank/seed.
* Replay consumes those Decision Cells instead of re‑deciding.
* Parameter changes are also cells, pointing back to the decisions and data that produced them.

So learning and exploration influence the *future*, but never make the *past* ambiguous.

---

**Q: How is a Focus Frame different from a feature vector?**
A Focus Frame is:

* small and **explicit**—you name exactly which signals and local hints it includes,
* based on a **shared Signal Field vocabulary**, so modules talk about the same signals,
* **governable**—policies can restrict which signals a learner is allowed to see, or how wide its peephole may be.

You can still think of it as “features” internally, but it’s a structured, limited view rather than an arbitrary blob.

---

**Q: What if the number of contexts (Focus Frames) explodes?**
That’s a signal that the Focus Frame is too fine‑grained. Remedies:

* bucket or coarsen local hints (e.g. length bins instead of exact lengths),
* drop signals that don’t clearly improve decisions,
* periodically merge rarely used keys or decay/GC Playbook entries that never recur.

If that still isn’t enough, you can move some complexity inside a single Playbook action (e.g. a small model) rather than exploding the number of Playbook keys.

---

**Q: How do Grounders fit into this; aren’t they just I/O?**
Grounders are I/O, but with learning‑aware semantics:

* they translate external signals into CEP metrics and CEI,
* they provide the raw data that the Signal Field is built from,
* they can be tuned themselves (e.g. thresholds, batching policies) via Playbooks if needed.

They are how the system feels and affects the external world, in a way that can drive learning.

---

**Q: How do humans interact with this learning system?**
Humans primarily operate at higher layers:

* inspect decisions, metrics, and Signal Field/mode history via perspectives and dashboards,
* adjust laws and policies about where exploration is allowed and how aggressive trainers can be,
* provide labels, overrides, and corrections (which feed into trainers and Playbooks),
* approve or reject reforms that promote or retire variants.

But even without those upper layers fully realized, the learning artifacts—Playbooks, Decision Cells, Signal Field, teach‑me cells—are all visible as data, so operators can inspect and debug behavior with normal CEP tools.

---

**Q: How does this scale across runtimes and federation?**
Each runtime has its own:

* Grounders,
* Signal Field,
* Focus Frames,
* Playbooks,
* Mode Clusters. 

Federation moves serialized frames and summaries between runtimes under `/net/**`, but there’s no single global Signal Field. Higher‑level flows can:

* merge or compare Playbook stats,
* share summary metrics,
* coordinate reforms (e.g. “variant X is winning globally for this Focus Frame, roll it out wider”).

Local loops remain independent and deterministic; cross‑node learning is a matter of merging small tables and applying governed changes, not sharing mutable global state.

---

**Q: How do I start using this pattern in a module?**

You can adopt it incrementally:

1. **Define a small Focus Frame** for your module:

   * choose a handful of signals from the Signal Field,
   * add a few local hints that clearly matter.

2. **Create a Playbook branch**:

   * for each Focus Frame key, list a finite set of actions (variants or strategies),
   * track attempts/success/cost for each action.

3. **Wire a Decide node**:

   * build the Focus Frame and key per decision,
   * consult the Playbook and pick an action,
   * emit a Decision Cell for every choice.

4. **Log feedback and update**:

   * record success/failure and cost,
   * update the Playbook row accordingly.

5. **Optionally add Imaginate**:

   * allow sampling in low‑risk environments or when certain signals (e.g. `teach`) are active,
   * record imaginate decisions like any other.

All of this is just cells and flows in the existing CEP kernel; the learning approach is a way of structuring behavior, not a separate engine.

---

## Addendum 1: Skills and the Plasticity Layer

This addendum introduces **skills** as first‑class learning concepts in CEP and explains how they stack to form a **plasticity layer** over Grounders and modules.

### A. What is a “skill” in CEP terms?

In CEP, a **skill** is not a special object type; it’s a particular way of using the existing learning primitives:

> **Skill** = a learner Flow (species/variant) whose behavior is defined by
> → a **Focus Frame** (what it sees),
> → a **Playbook** (what it can do),
> → and **feedback** (how it updates its choices).

Concretely:

* The skill is implemented as a **Flow** in the ecology layer (`/data/eco/flows/**`), attached to a species/variant and run as organisms under `/data/eco/runtime/organisms/**`.
* For each decision:

  * It builds a Focus Frame from the **Signal Field** plus local context.
  * It derives a Focus Frame key and looks up a row in its **Playbook**:

    ```text
    /data/eco/runtime/playbooks/<skill_name>/<focus_key>
    ```
  * It selects an action (deterministic or imaginate) from that finite set and emits a **Decision Cell**.
* Later Transform nodes measure outcomes, write feedback linked to the Decision Cell, and update the Playbook row for that Focus Frame key.

A skill is therefore “just” a learner with an explicit scope (what it is allowed to change) and a well‑defined Focus Frame/Playbook pair.

### B. Skills and Grounders

Grounders turn the outside world (I/O, UI, network, storage, etc.) into metrics and CEI, which are aggregated into the **Signal Field**.

Skills sit **on top of Grounders**:

* They *read* the Signal Field plus domain‑specific hints (input size, cohort flags, pipeline metadata, etc.) into their Focus Frames.
* They *act* by:

  * choosing variants or paths for modules,
  * adjusting parameters or budgets,
  * tuning exploration (Imaginate) policies,
  * or writing new entries into Playbooks or `/data/learn/**` for downstream modules.

In this sense, Grounders provide the “body signals” and skills provide “ways of responding” that can be improved over time.

### C. The Plasticity Layer: stacking skills

The **plasticity layer** is the stack of skills that make CEP adaptable. It has three conceptual tiers, all using the same mechanics (Flows + Focus Frames + Playbooks):

#### 1. Base skills (Level 0)

Base skills operate directly on modules and Grounders.

* **Examples**:

  * A latency tuning skill that chooses between “fast but rough” vs “slow but precise” variants of an operation, based on `fast`, `io_pressure`, and error metrics.
  * A layout skill that selects between different UI templates, based on `visual_strain`, `user_confused`, and simple content stats.

* **Scope**: individual modules or limited subsystems.

* **Focus Frames**: narrow; mostly a few signals plus local hints.

* **Actions**: “pick this variant/path/strategy for this module.”

These are the “reflexes” of the system.

#### 2. Coordination skills (Level 1)

Coordination skills manage **many** base skills at once.

* **Examples**:

  * A resource coordination skill that sets exploration bias and variant preferences across multiple modules when `fast` and `io_pressure` are high.
  * A UX coordination skill that chooses “training mode” vs “expert mode” for whole groups of UI skills, based on `visual_strain` and behavioral metrics.

* **Scope**: collections of base skills and modules.

* **Focus Frames**: aggregates of signals and metrics from several Grounders and learners.

* **Actions**: “set policy mode” or “tune parameters” for families of Playbooks (e.g., raising/lowering exploration bias, switching between safety profiles).

These skills operate like “cognitive style” and resource managers within the ecology.

#### 3. Meta‑skills (Level 2, skills‑of‑skills)

Meta‑skills are **skills about skills**: their Focus Frames include metrics and decisions *from other skills*.

* **Examples**:

  * A teacher skill that decides how to respond to teach‑me escalations from other learners, and how to propose new Playbook entries or adjustments.
  * An exploration manager skill that dynamically adjusts Imaginate policies across the system, based on how exploration is performing.
  * A “wisdom” skill that selects which coordination style to use (cautious, exploratory, recovery, etc.) given the current Signal Field and Mode Cluster state.

* **Scope**: other skills’ Playbooks and policies.

* **Focus Frames**:

  * contain summaries of other skills’ metrics (e.g. success rates, instability, human override frequency),
  * may include current Mode ID (`NormalOperation`, `OverprotectiveGuard`, etc.), provinces, and high‑level objectives.

* **Actions**:

  * adjust other skills’ exploration_bias,
  * enable/disable variants globally in certain provinces,
  * select “skill ensembles” for certain pipelines (“use skill A for this domain, skill B for that”).

Meta‑skills are not special in the kernel; they are simply skills whose actions target **other learners’ configuration and Playbooks** instead of user‑facing behavior.

### D. Cascaded / recursive skill graph

Skills naturally form a **directed acyclic graph** (DAG):

* **Edges downwards**: a skill’s actions influence:

  * modules, Grounders, or lower‑level skills (by changing their Playbooks, parameters, or modes).
* **Edges upwards**: a skill’s Focus Frame includes:

  * signals and metrics produced by lower‑level skills and Grounders.

In general:

* Level‑0 skills depend on Grounders and module metrics.
* Level‑1 skills depend on Level‑0 metrics and decisions.
* Level‑2 skills depend on Level‑1 and Level‑0 metrics and decisions.

Because every decision is a **Decision Cell**, and every metric is stored in `/data/eco/metrics/**`, all these dependencies are visible and replayable.

### E. Where skills live in L1/L2

* **Layer 1 (Coherence & Pipelines)**

  * Pipelines orchestrate when skills run:

    * per‑request pipelines calling base skills,
    * periodic or triggered pipelines calling coordination and meta‑skills.
  * Pipelines annotate work with `pipeline_id` and `stage_id`, which is part of the local context used in Focus Frames.

* **Layer 2 (Ecology & Flows)**

  * Skills are expressed as species/variants/flows with:

    * Focus Frame helpers,
    * Playbooks in `/data/eco/runtime/playbooks/**`,
    * metrics in `/data/eco/metrics/**`,
    * Decision Cells in `/data/eco/runtime/decisions/**`.

No new kernel features are required; “skill” is a conceptual role for learners built from existing CEP primitives.

---

## Addendum 2: Social Lexicons and Shared Meaning

This addendum explains why **lexicons in CEP are inherently social**, and how that fits into the learning approach (Grounders, Signal Field, Focus Frames, Playbooks, skills, and meta‑skills).

### A. Private labels vs social lexicons

A single learner can maintain **internal tags** for patterns it experiences (e.g. a local name for “this hurts” or “this seems safe”). But a **lexicon** in the language sense is more than that:

> A lexicon is a **shared mapping** from tokens (words)
> to patterns of experience (signals, modes, behaviors)
> that **many minds** in a community can use.

For a word to have “real” meaning in this sense:

1. Multiple minds (runtimes, organisms, or humans) must have:

   * similar experiences (Grounders + metrics),
   * similar internal attractors (Signal Field + Mode Clusters),
   * and attach the *same-ish token* to those patterns.
2. Saying or hearing the word should reliably nudge their **Signal Field** in similar ways (e.g. raising `risk`, `teach`, `low_noise`, etc.).

If a mapping exists only in one learner, it is a **private label**, not a social lexicon. The learning approach therefore treats lexicon entries as **social artifacts** that sit above individual skills.

---

### B. Where social lexicons live in the CEP stack

CEP already has a place for social structures and shared artifacts:

* **Layer 2 – Ecology & Flows**

  * Local learners and skills (including language‑aware skills) live here and may reference lexicon entries.

* **Layer 3 – Awareness & Datasets**

  * Shared datasets, perspectives, and tools where many minds’ behavior and experience are visible together.

* **Layer 4 – Governance & Self‑Evolution**

  * Laws, reforms, councils, and provinces that manage how shared artifacts (including lexicons) are allowed to change.

Within this layering:

1. **L2** uses lexicon entries to interpret language and to decide how words should affect the Signal Field and skills.
2. **L3** collects evidence about how words are used and what patterns they co‑occur with.
3. **L4** treats lexicons as governed artifacts, with laws and reforms controlling how tokens and their mappings evolve.

---

### C. Lexicon entries as pattern hooks

In the learning approach, each lexicon entry is not just a string. Conceptually it is a **hook into shared patterns**:

* **Signal profile** – which signals in the Signal Field are typically raised/lowered when this word is used:

  * e.g. `"dangerous"` → `risk ↑`, `teach ↑`, `low_noise ↓`.

* **Mode associations** – which Mode Clusters this word tends to appear in:

  * e.g. `"home"` → calm, safe modes;
  * `"trap"` → anxious, over‑protective modes.

* **Grounder patterns** – typical grounder metrics that co‑occur:

  * e.g. `"shock"` → reward/pain grounder metrics;
  * `"dark corner"` → UI/vision or proximity grounder patterns.

* **Skill hooks** – which skills should treat this word as advice, warning, or training signal.

A lexicon entry for `<word>` thus acts like:

```text
<word> → {
  signals_hook:  {...},
  modes_hook:    {...},
  grounders_hook:[...],
  skills_hook:   [...]
}
```

Language Grounders and language‑aware skills use these hooks to:

* update the Signal Field when they observe the token,
* create **synthetic Focus Frames** and hypothetical outcomes from utterances,
* drive training-by-simulation (e.g. stories, warnings) instead of only learning from direct grounder experience.

---

### D. Social shaping of lexicons (L3 and L4)

Because lexicons are social, they must be shaped and maintained **across minds**, not just inside one learner:

#### D.1 Layer 3 – Evidence and perspectives

Layer 3 can host:

* **Lexicon datasets**:

  * utterances paired with Signal Field snapshots, Mode IDs, and skills’ behavior at those times;
  * e.g. “when we say ‘dangerous’, the system is typically in these modes, with these signals high.”

* **Perspectives** that let humans and meta‑skills inspect:

  * how each word is actually used across runs, provinces, and runtimes,
  * how stable or ambiguous each mapping is.

Based on that evidence, specialized skills (or humans) can propose:

* adding new tokens,
* refining existing mappings,
* deprecating tokens that have become misleading.

#### D.2 Layer 4 – Lexicon as law‑governed artifact

Lexicon branches can be treated like other governed artifacts:

* **Lexicon laws**:

  * define which tokens are canonical in each province,
  * define constraints on how they map to signals/modes,
  * specify compatibility across versions.

* **Lexicon reforms**:

  * propose adding/removing/renaming tokens,
  * update mappings (e.g. “in this province, ‘dangerous’ now includes a new kind of risk”),
  * specify rollout and rollback plan.

Councils can then approve or reject lexicon reforms, just like they do for pipelines, models, or other packs. This makes meaning **explicitly social and governed** rather than an ad‑hoc byproduct of local training.

---

### E. Social lexicons even in a minimal “rat mind”

Even in a small “rat‑like” CEP mind, language is already social in the minimal sense:

* At least two minds are involved:

  * a **trainer** (human or other agent) that uses tokens like `left`, `food`, `shock`, `safe`,
  * a **learner** (the rat mind) that interprets those words as updates to its Signal Field and Playbooks.

The shared lexicon ensures that:

* when the trainer says “left corridor is dangerous,”
* both sides agree roughly that:

  * “left corridor” maps to a certain spatial context,
  * “dangerous” implies high `risk` and negative outcomes if certain actions are taken.

The lexicon is therefore:

* rooted in **shared experience** (one agent has actually been shocked there),
* used to transfer that experience to another agent via words,
* maintained as a **shared artifact** for that rat–trainer community.

This is already a small social symbol system, even without full human‑scale language.

---

### F. Relation to Mode Clusters and Jung‑style symbolism

Mode Clusters (recurrent attractors of behavior + feelings) can acquire **names** in the lexicon when they matter socially:

* A frequently occurring Mode Cluster (e.g. over‑protective behavior) might be labeled `"guardian mode"`.
* That token then becomes a handle for the entire pattern:

  * used in logs, dashboards, and operator panels,
  * used in training language for meta‑skills,
  * and, potentially, in dialogue with humans.

This is analogous to Jungian symbolism:

* “Archetypes” in this framing are **Mode Clusters** that appear across many agents and contexts.
* Lexicon entries for those patterns are **social names** for shared attractors in behavior and feeling.

Language Grounders and skills can then treat such words as **strong, pattern‑activating signals**:

* hearing `"guardian mode"` in a command or story can shift the Signal Field toward the corresponding mode attractor,
* enabling “talking to” the system about its own inner states in a controlled, social way.

---

### G. Summary

* Lexicons are **not purely individual**; they are shared mappings from tokens to experience patterns that many minds use.
* In CEP, that means:

  * local skills and language Grounders use lexicon entries to interpret tokens into Signal Field changes and hypothetical outcomes (L2),
  * shared datasets and perspectives observe and refine how words are actually used (L3),
  * and laws/reforms treat lexicons as governed artifacts that can evolve across provinces and runtimes (L4).
* Even in minimal settings (like a rat‑like mind trained by a human), lexicons are inherently social: they sit between trainer and learner, not only inside one learner’s head.
