# Self-Hosting Thesis

This document is the **canonical statement of the ultimate goal** for the AI-Agent-Factory project.

It is kept in `reference-docs/` because it defines a stable project thesis rather than a phase-specific roadmap.

It is written for readers who do **not** already know the project vocabulary.

## Plain-English Thesis

The ultimate goal of AIAF is:

> **Wasm-Biotic creating Wasm-Biotic.**

In plain language, that means we want to build a system that can eventually help create, test, improve, and replace later versions of itself.

This does **not** mean the system should rewrite itself freely or change anything it wants.

It means the system should be able to produce new versions of its own factories and support systems in a **controlled, testable, and reviewable way**.

## A Simple Analogy

A useful analogy is a compiler that eventually becomes able to compile the next version of itself.

The self-hosting goal for AIAF is similar, but larger in scope.

Instead of only producing one program, the system would eventually be able to produce and improve:

- its own factory logic,
- its own worker agents,
- its own supervisor agents,
- its own memory and orchestration services,
- and its own capability interfaces.

## What “Wasm-Biotic” Means Here

For the purpose of this document, **Wasm-Biotic** is the project’s structured substrate for creating and improving software artifacts through:

- typed internal representations,
- semantic validation,
- Wasm component packaging,
- explicit interface boundaries,
- immutable storage,
- lineage tracking,
- and governed promotion of accepted results.

The important idea is that Wasm-Biotic is **not** supposed to work by casually editing old code in place.

Its preferred pattern is:

1. generate a new candidate artifact,
2. validate it,
3. package it behind explicit boundaries,
4. record its lineage and evidence,
5. and only then allow it to be promoted into use.

## What “Self-Hosting” Means Here

In this project, **self-hosting** means that the Wasm-Biotic ecosystem eventually contains enough of its own factory machinery that it no longer depends on an external agent framework for its core improvement loop.

In other words:

- the system can create new worker and supervisor artifacts,
- the system can evaluate those artifacts using its own validation machinery,
- the system can package and store those artifacts using its own substrate,
- and the system can promote better versions into the next usable generation.

## The More Precise Thesis

The more precise version of the goal is:

> Wasm-Biotic should eventually internalize the full agentic harness required to create, evaluate, promote, and replace Wasm-Biotic-native factories under explicit lineage, policy, and boundary control.

This sentence has a lot packed into it, so the key terms are unpacked below.

## Key Terms

### Agentic harness

The **agentic harness** is the control system around the model or agents.

It includes things like:

- task execution loops,
- orchestration,
- memory handling,
- approvals,
- policy checks,
- tool access,
- and background operation.

The harness matters because a raw model by itself is not enough.

### Wasm-Biotic-native factories

These are factories built using Wasm-Biotic’s own architecture and components, rather than being managed mainly by an outside framework.

### Lineage control

**Lineage** means the system can show where a new artifact came from:

- what it was derived from,
- what mutations or changes led to it,
- what evidence was used to accept it,
- and how it entered the system.

### Policy control

**Policy** means the system follows explicit rules about what it is allowed to do, what must be validated, what requires approval, and what is too risky to promote automatically.

### Boundary control

**Boundary control** means different parts of the system interact through explicit interfaces rather than hidden shared state or ambient authority.

In Wasm-Biotic, these boundaries are important because they make capability, state, and responsibility visible.

## What This Goal Means In Practice

If the self-hosting thesis is achieved, the ecosystem would be able to do the following:

- build candidate new versions of its own factories and supervisors,
- test those candidates through semantic and policy validation,
- run them through explicit capability boundaries,
- compare them against existing versions,
- store them as traceable artifacts,
- and promote better versions into future epochs of the system.

That would mean Wasm-Biotic is no longer just producing other software.

It would also be producing the next generation of the machinery that produces software.

## What This Goal Does Not Mean

The self-hosting thesis does **not** mean:

- unrestricted self-modification,
- arbitrary mutation of any source tree,
- hidden authority or hidden state,
- letting LLMs decide truth on their own,
- or collapsing all parts of the architecture into one undifferentiated loop.

The system still has to stay:

- bounded,
- inspectable,
- validated,
- replayable,
- and governed.

## Why This Matters

If this works, AIAF becomes more than a one-off agent or developer tool.

It becomes a **self-improving software ecosystem** with explicit rules for how better versions are created and adopted.

That is the real long-term promise of the project.

## How We Would Know We Reached It

The ultimate goal can be considered materially realized when all of the following are true:

1. A Wasm-Biotic-native supervisor can coordinate worker agents.
2. Those workers use Wasm-Biotic-native capability interfaces and services.
3. Memory, validation, review, and promotion are handled by Wasm-Biotic-native artifacts and infrastructure.
4. New factory or supervisor generations are produced inside the same governed pipeline.
5. The ecosystem can adopt a better factory generation without losing lineage, replayability, or authority control.

## The Practical Transition Strategy

We do not need to start in a fully self-hosting state.

The practical path is:

1. use external or imported agentic capabilities where needed,
2. map those capabilities onto Wasm-Biotic concepts,
3. reimplement them natively inside Wasm-Biotic,
4. and then let those native capabilities help produce their successors.

That is how the system moves from “inspired by an external North Star” to “self-hosting on its own substrate.”

## Final Statement

The ultimate goal of AIAF is not simply to build a strong AI agent.

The ultimate goal is to build a **Wasm-Biotic ecosystem that can responsibly participate in building its own next generation**.
