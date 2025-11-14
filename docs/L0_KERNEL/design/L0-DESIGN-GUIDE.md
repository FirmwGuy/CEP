# L0 Design: Document Guide

## Introduction
Design documents capture the architectural story behind Layer 0 implementations. They explain why an API or subsystem looks the way it does, how alternatives were weighed, and which invariants the code now relies on. Read this guide before drafting a new `L0-DESIGN-*.md` so design intent stays consistent with the rest of CEP’s documentation stack.

## Technical Details
- **Placement and naming**  
  - Create files under `docs/L0_KERNEL/design/` as `L0-DESIGN-<topic>.md`.  
  - Use `<topic>` names that match the code feature or module (`HEARTBEAT`, `SERIALIZATION`, `PROXY-CELLS`, etc.) so cross-references remain obvious.

- **Audience and scope**  
  - Speak to engineers who already know the API surface (they have read the Overview, Algorithms, and Integration guides) but need to internalise the rationale before changing behaviour.  
  - Focus on decisions that affect determinism, performance bounds, replay, and compatibility guarantees. Leave implementation walkthroughs to the Integration guide.

- **Structure**  
  1. **Nontechnical summary** – one or two paragraphs stating the problem, goals, and the mental model outsiders should hold.  
  2. **Decision record** – the key choices, invariants, and rejected alternatives. Capture what must stay true for the implementation to be correct.  
  3. **Subsystem map** – how the design touches files, helper APIs, and data structures (with links into headers/source).  
  4. **Operational guidance** – flags, metrics, or failure modes engineers must watch when extending the design.  
  5. **Change playbook** – how to approach refactors safely (tests to run, feature gates to toggle, docs to reread, TODOs to update).  
  6. **Global Q&A** – short answers to the questions reviewers or future maintainers repeatedly ask about the design.

- **Relationship to other docs**  
  - **Overview** explains the territory; **Design** documents justify the current route through it.  
  - **Integration** guides show how to use the APIs and wire them into packs.  
  - **Algorithms** focus on cross-cutting mechanics.  
  - **Design docs** should link to those references but avoid duplicating procedural steps or low-level implementation lists.

- **Workflow expectations**  
  - Draft a design doc when introducing a new subsystem, altering observable behaviour, or locking in a major trade-off.  
  - Cross-link the relevant planning notes so ongoing work stays synchronised without sending readers hunting through ad-hoc task lists.  
  - Update `docs/DOCS-INDEX.md` and `docs/DOCS-ORIENTATION-GUIDE.md` after adding a Design doc so navigation remains current.

## Global Q&A
- **When do I need a Design doc instead of expanding the Overview?**  
  Use a Design doc when the change introduces new invariants or trade-offs. Overviews remain high-level; they do not replace the need to record “why” decisions.

- **Can I skip sections if they feel empty?**  
  Keep all major headings, even if a section is brief. Empty sections signal missing analysis—fill them before shipping the feature.

- **How detailed should the change playbook be?**  
  Capture the minimum to keep future refactors safe: required tests, metrics to watch, and the order of operations when revisiting the design.

- **Do I need to version Design docs?**  
  No, but record the date and context of major revisions at the top so reviewers can trace when decisions shifted.
