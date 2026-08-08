# Explainer: What Wasm-Biotic Is, Where It Is Going, and What Exists Today

This document is for a reader with no prior exposure to Wasm-Biotic or AIAF.

It explains:

- the big idea behind `Wasm-Biotic`
- the long-range `North Star`
- the role of `AIAF`
- what the live system can actually do today
- what is still downstream

## The Short Version

This project is trying to answer a hard question:

> Can software improve itself in a controlled, testable, reviewable way instead of being patched in place forever?

`Wasm-Biotic` is the architectural answer.

`AIAF`, the `AI-Agent-Factory`, is the governed supervisory system being built on top of that architecture.

The long-range North Star is:

> **Wasm-Biotic creating later Wasm-Biotic generations without losing safety, evidence, control, or rollback.**

The current live system does not fully achieve that North Star.

What it does achieve is still significant:

> the repo now contains a real bounded `aiaf-v1` implementation whose stable `execution` contract completes the bounded `v01`/`RC05` supervisory arc, and whose local operator/readout surface now carries tested `v1.5` through `v2.9` views and workspaces without changing that contract.

That means the project is no longer only a design idea and no longer only a test harness. It is already a real local system that can be run, inspected, replayed, steered, and audited, even though it is not yet a full Wasm-Biotic-native self-hosting ecosystem.

## Start With the Problem

Most software gets better by directly editing the old code.

That is normal, but it creates familiar problems:

- changes are hard to trace
- hidden side effects accumulate
- rollback is painful
- authority gets blurry
- systems become harder to reason about as they grow

Wasm-Biotic is trying a different pattern.

Instead of saying "keep changing the old thing until it seems good enough," it says:

1. create a new candidate
2. validate it
3. package it behind explicit boundaries
4. record lineage and evidence
5. compare it with what already exists
6. adopt it only if it is genuinely better and still safe

That is the core idea.

## What "Wasm-Biotic" Means

Wasm-Biotic is the foundational architecture underneath the project.

The biological language is a metaphor. The underlying idea is simple:

- small parts can be combined into larger parts
- larger parts can be tested and packaged
- accepted parts can later become reusable building blocks
- the system should grow by producing new compatible artifacts

The most important principle is this:

> Wasm-Biotic prefers to grow by synthesizing new artifacts, validating them, and promoting them, rather than by casually mutating old artifacts in place.

### A Simple Mental Model

Think of Wasm-Biotic as a factory for software artifacts:

```text
small approved parts
        |
        v
candidate composition
        |
        v
semantic validation
        |
        v
explicit packaging
        |
        v
stored artifact with lineage
        |
        v
possible promotion into use
```

The point is not just "can it build?" The point is "can it be understood, validated, governed, and safely adopted?"

## Why WebAssembly Matters

The "Wasm" in Wasm-Biotic refers to `WebAssembly`, especially WebAssembly components.

For a lay reader, the important part is not browsers. It is this:

- components communicate through explicit interfaces
- boundaries are visible instead of hidden
- packaging is portable
- capabilities can be granted deliberately instead of assumed implicitly

In plain language, WebAssembly helps the project build pieces that are easier to isolate, compare, and safely compose.

In the live root package today, that still functions more as a northstar architectural constraint than as a fully implemented Wasm component toolchain.

## Two Layers of the Architecture

One of the key ideas in Wasm-Biotic is that there are two different kinds of composition happening.

### 1. Local composition

Inside the system, small typed building blocks are combined into candidate structures.

This is the construction layer.

### 2. Boundary composition

At the edges, packaged components interact through explicit interfaces and capability boundaries.

This is the deployment and interaction layer.

```text
inside the box:
  combine typed building blocks into candidate structures

across the boundary:
  components interact through explicit interfaces and capabilities
```

The project keeps those separate on purpose, because hidden mixing of logic, memory, power, and tool access is exactly what makes systems hard to govern.

## What AIAF Adds

AIAF stands for `AI-Agent-Factory`.

If Wasm-Biotic is the substrate for producing and validating artifacts, AIAF is the governed supervisory machinery built on top of that substrate.

That means AIAF is about:

- supervisors
- workers
- task execution loops
- memory handling
- capability access
- approvals
- governance
- promotion decisions
- rollback and quarantine

The relationship is:

```text
Wasm-Biotic
  = the substrate for generating, validating,
    packaging, storing, and promoting artifacts

AIAF
  = the supervisory system built on top of that substrate
    so agents and factories can operate in a governed way
```

## The Fundamental Vision

The fundamental vision is not "an AI that can do anything."

It is closer to this:

> Build a software ecosystem that can generate, test, compare, govern, and eventually improve later versions of software artifacts while keeping authority, evidence, boundaries, and rollback explicit.

That leads to a different style of system design.

### What the project wants more of

- explicit interfaces
- explicit capabilities
- durable evidence
- semantic validation
- replayable execution
- governed promotion
- bounded experimentation

### What the project wants less of

- hidden state
- ambient authority
- arbitrary self-modification
- "trust me, it seems fine"
- editing old systems in place without lineage

## What "North Star" Means

"North Star" means the long-range destination.

For this project, the North Star is:

> **Wasm-Biotic creating Wasm-Biotic.**

That is the shortest useful version of the ambition.

In plain language, the project wants a future system that can help:

- create new factory logic
- create better workers
- create better supervisors
- evaluate those candidates
- compare them to the incumbent
- adopt better ones safely

### What the North Star Is Not

This is just as important.

The North Star does not mean:

- unrestricted self-rewriting
- runaway autonomous mutation
- hidden power
- replacing human review with vibes
- letting a model silently decide what becomes true

The North Star is about responsible self-improvement, not free-form self-modification.

## The Practical Strategy

The project does not assume it starts self-hosting on day one.

The practical strategy is:

```text
import useful agentic capabilities first
            |
            v
map them onto Wasm-Biotic concepts
            |
            v
rebuild them natively inside Wasm-Biotic
            |
            v
let those native capabilities help produce their successors
```

That is why the North Star is best understood as a capability target, not a product-cloning exercise.

## Where the Current System Fits

The live root package in this repo is `aiaf-v1`.

The safest way to understand the naming is to keep two clocks separate:

1. `v01` / `RC01` through `RC05`
   = the bounded execution-kernel arc.
   This arc is materially complete in the live root package.

2. `v1.5` through `v1.9` and `v2.0` through `v2.9`
   = the local operator surface, readout, and transition-readiness line layered on top of the stable kernel contract.
   These labels describe runnable local demos, workspaces, views, and acceptance-backed readouts. They do not mean the North Star has already been achieved.

So when someone asks "what exists today?", the right answer is:

- the live package is `aiaf-v1`
- the stable public contract is still the bounded `execution` kernel
- the bounded `v01` supervisory arc is complete in the live root package
- the local operator/readout surface now carries tested layers through `v2.9`
- the full Wasm-Biotic northstar remains downstream

## A Simple Journey Map

```text
North Star
  Wasm-Biotic creating later Wasm-Biotic generations
            ^
            |
   downstream beyond the live root package
            ^
            |
operator/readout line
  v2.9  convergence, unresolved pressure, next-line handoff
  v2.8  self-hosting transition gate and milestone language
  v2.7  bounded factory operations
  v2.6  native-service generation review
  v2.5  integrated generation dossier
  v2.4  governance-release closure
  v2.3  runtime topology and contention readouts
  v2.2  continuity-service readouts
  v2.1  capability-service readouts
  v2.0  contract-foundation readouts
  v1.9  convergence and v2 transition workspace
  v1.8  experiment-program workspace
  v1.7  scenario studio, replay, analytics, context packages
  v1.6  operator cockpit, history, evidence, adoption workspace
  v1.5.1 system overview, progress tracker, Factory and Agent views
  v1.5  runnable local system and observer console
            ^
            |
bounded execution kernel
  v01 / RC05 complete bounded supervisory arc
```

## What the Current System Fully Does Today

Below is the current practical capability surface, explained in plain language.

### 1. It runs as a real local system

The repo is no longer only a library and acceptance harness.

It has a runnable local entrypoint:

- `aiaf-v1-runner`

That lets a user:

- list curated scenarios
- launch the local observer console
- run a scenario headlessly
- export a durable run bundle

In plain language, the system can now be started and used as software, not only inspected as source code.

The current runner is intentionally curated. It exposes six replayable local scenarios rather than a general autonomous workload launcher.

### 2. It runs a governed supervisor system

The system has real lifecycle states for work.

It can distinguish between:

- starting work
- being ready to act
- waiting for approval
- waiting for worker output
- completing
- failing
- containing or reversing unsafe transitions

This matters because it makes the system deterministic and replayable instead of improvisational.

### 3. It enforces explicit capability rules

Workers and supervisors do not just "have power."

They operate inside explicit structures such as:

- capability envelopes
- authority classes
- approval classes
- isolation profiles
- allowed resource scopes

In plain language:

```text
actor wants to do something
        |
        v
system checks:
  "is this world allowed?"
  "is this operation allowed?"
  "is this scope allowed?"
  "does this require approval?"
        |
        v
allow / wait / block / quarantine
```

So the project already has a serious answer to the question:

> How does the system stop an agent from just doing things because it feels like it?

### 4. It can checkpoint, pause, and resume safely

Before sensitive transitions, the system can capture a checkpoint.

That lets it:

- pause safely
- wait for approval
- recover after interruption
- resume from durable state
- roll back to a known checkpoint when needed

That is a major difference from a loose prompt loop.

### 5. It has skeptical memory, not just chat history

The memory system is structured.

It uses things like:

- pointer indexes
- transcript slices
- topic bundles
- checkpoint artifacts
- approval artifacts
- audit artifacts
- contradiction records
- consolidation jobs

The memory model is trying to answer:

- what happened?
- why did it happen?
- what evidence supported it?
- what was deferred?
- what was approved?
- what was safe to resume?

```text
event happens
   |
   v
checkpoint / approval / result / audit
   |
   v
durable evidence
   |
   v
later reconstruction:
  "what changed?"
  "who approved it?"
  "what checkpoint was safe?"
  "why was this adopted or rejected?"
```

### 6. It can coordinate bounded workers

The system can route work across multiple bounded workers and synthesize the results.

That includes:

- task graphs
- dependency tracking
- routing decisions
- ownership boundaries
- bounded recovery
- synthesis handoffs

So this is already beyond a single-agent demo loop.

### 7. It can compare challengers against incumbents

The system can run a challenger in shadow mode and compare it against the current incumbent.

That means it can ask:

- did the challenger run under the same input conditions?
- did it stay within the allowed boundaries?
- did it produce acceptable results?
- is it promotion-ready?

This is a core part of the self-improvement story.

### 8. It can govern promotion, quarantine, and rollback

If a challenger looks better, the system can produce promotion evidence and govern the move into the next epoch.

It also keeps durable records such as:

- promotion acts
- epoch adoption records
- reversal windows
- quarantine records
- rollback handles

In plain language, adoption is treated as a governed act, not a casual swap.

### 9. It can run a continuous governed factory program

The `v1.4` line pushed the project from a one-off bounded proof into a repeated governed program.

The system now explicitly models and preserves evidence for:

- campaign portfolios
- budgets and intervention windows
- review load
- canary evidence
- release evidence
- rejection evidence
- repeated background continuity
- plan carry-forward
- reprioritization
- contention and fairness
- operator steering
- rollback rehearsal
- adoption safety

This is the difference between:

```text
"we proved the loop once"
```

and

```text
"we can run the loop as an ongoing governed program"
```

### 10. It has a real operator cockpit

The local console is not just a pretty wrapper around logs.

It already gives the operator structured views for:

- system overview
- run history
- portfolio state
- evidence drill-down
- operator runbooks
- Factory view
- Agent view
- run evidence

That means the system can now be observed and steered by a human through a coherent local surface.

The important constraint is that the current governed actions are still exposed through curated demo paths rather than a general-purpose operator control plane.

### 11. It has a scenario studio and replay workspace

This is what the later local operator/readout line adds on top of the earlier local runner stages.

The system now supports:

- governed scenario templates
- Factory rehearsal packs
- Agent rehearsal packs
- replay from checkpoints and approval boundaries
- branch inspection
- structured multi-run diffs
- portfolio analytics
- reusable operator-context packages

In plain language, the system can now be used to learn from runs, not only execute them.

That changes the operator's role from:

```text
"watch the current run"
```

to:

```text
"design a bounded experiment, run it, replay it, compare it,
 and carry the lessons forward"
```

## A Simple Picture of the Current System

```text
curated scenario or rehearsal pack
            |
            v
local runner starts session
            |
            v
supervisor proposal / action / routing decision
            |
     +------+------+
     |             |
     v             v
approval needed?   bounded worker path
     |                  |
     v                  v
checkpoint + wait   dispatch + result
     |                  |
     v                  v
resume            supervisor synthesis
     \                  /
      \                /
       v              v
     evidence + memory + audit updates
              |
              v
   compare / retain / promote / quarantine / rollback
              |
              v
   observer console + history + replay + analytics
              |
              v
 repeated governed learning cycle under stable interfaces
```

## A Simple Picture of the Operator Surface

```text
System Overview
   |
   +--> "what exists today?"
   +--> "what is Wasm-Biotic already?"
   +--> "what is still future?"
   |
   v
Factory / Agent views
   |
   +--> "what is the factory doing?"
   +--> "what are the workers doing?"
   |
   v
History / Evidence / Operator
   |
   +--> "what happened?"
   +--> "why was it approved?"
   +--> "what can I safely do now?"
   |
   v
Scenario Studio / Replay / Analytics
   |
   +--> "what should we try next?"
   +--> "what branch point mattered?"
   +--> "what changed across runs?"
```

## A Simple Picture of the Growth Path

```text
incumbent
   |
   v
shadow challenger evaluation
   |
   v
comparison + sufficiency evidence
   |
   v
promotion readiness
   |
   v
promotion act + adoption + reversal window
   |
   v
successor campaign
   |
   v
successor genome -> phenotype -> semantic validation
   |
   v
continuous factory program
   |
   v
scenario studio + replay + analytics
```

## What Still Does Not Exist Yet

This is just as important as what does exist.

The current live system still does not mean:

- open-ended autonomous self-improvement
- arbitrary interface evolution
- unrestricted source-tree rewriting
- a live Wasm/WIT/component packaging pipeline in the root package
- federated multi-factory coordination
- cross-repository replacement campaigns
- hosted multi-user operation
- a complete self-hosting Wasm-Biotic ecosystem

The current contract is still closer to this:

> improve inside stable interfaces, keep authority explicit, keep the evidence, stay runnable, and stay governable.

## Why That Constraint Matters

Projects like this fail when they try to do everything at once.

This project is taking the opposite approach:

- keep interfaces stable
- keep authority explicit
- keep evidence durable
- add capability in bounded slices
- prove each step before claiming the next one

That makes the work slower than hype, but much more serious as engineering.

## Why the Project Matters

If this project succeeds over time, it points toward a different model of software evolution:

- not endless patching of old systems
- not hidden autonomous loops
- not "just trust the agent"

Instead:

- new artifacts are created deliberately
- better versions are compared against current ones
- adoption is governed
- rollback remains possible
- memory and evidence stay attached
- the system can be run and inspected locally
- and the system gradually becomes capable of helping build its own next generation

That is why the long-range promise is bigger than "an AI coding assistant."

The real promise is a governed self-improving software ecosystem.
