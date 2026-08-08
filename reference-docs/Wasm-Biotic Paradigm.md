# Wasm-Biotic Paradigm

## I. The Core Question

Wasm-Biotic starts from a simple question:

**Can we grow useful programs from small, trusted parts instead of repeatedly rewriting large mutable systems by hand?**

This project is an attempt to answer that question in a disciplined way. The goal is not "software that behaves like life" in a mystical sense. The goal is a system where change happens by:

- discovering new compatible structures
- validating them before adoption
- packaging them behind explicit interfaces
- preserving them as immutable artifacts that can be reused later

That is the core direction of the project.

## II. Directional Vision

The Wasm-Biotic Paradigm is a design for building software that changes by **synthesis and replacement**, not by casual mutation of existing artifacts.

In practical terms, the project is moving toward a pipeline that:

1. searches over a finite library of approved building blocks
2. composes candidate programs as typed graphs
3. checks them against semantic requirements
4. packages accepted results as WebAssembly components
5. stores accepted artifacts with explicit compatibility and content identity
6. reuses successful artifacts as future building blocks

If that works, the system gains a form of controlled growth. New behavior appears as a new accepted artifact, not as a hidden in-place edit to an old one.

## III. Why The Metaphor Exists

The biology metaphor is meant to make the system easier to picture.

It is useful because it emphasizes:

- explicit boundaries
- local composition rules
- reusable structure
- accumulated history
- growth by recombination rather than patching

But the metaphor is not the normative language of the architecture. The real system is about typed libraries, typed DAGs, semantic validation, WIT interfaces, Wasm components, and immutable artifact storage.

If the metaphor makes the project harder to understand, the system vocabulary wins.

## IV. Plain-Language Model

The project uses a few recurring terms:

| Metaphor | Standard meaning |
|----------|------------------|
| atom | a small approved building block |
| molecule | a composed candidate program |
| macromolecule | a promoted higher-order composite built from accepted molecules or composites |
| cell | a packaged Wasm component |
| assembly | a membrane-aware structure that binds multiple accepted artifacts into a larger unit |
| membrane | a WIT world or interface boundary |
| organelle | an explicit stateful resource behind a boundary |
| mitochondrion | an encapsulated external program that powers the system through explicit API exchange |
| fossil | an accepted immutable artifact stored for reuse |

The architecture has **two distinct composition regimes**.

### 1. Local chemistry

Inside the synthesis substrate, the system composes small pure building blocks using a strict internal type algebra.

This is the domain of:

- approved atoms
- typed DAG construction
- bounded search
- semantic validation

The local question is: **can these pieces form a correct closed program?**

### 2. Boundary chemistry

Across components, the system composes through WIT imports and exports.

This is the domain of:

- WIT worlds and interfaces
- Canonical ABI behavior
- Wasm component packaging
- resource boundaries
- runtime linking and instantiation

The boundary question is: **can this accepted program interact with other software through an explicit contract?**

These regimes must not be collapsed into one rule.

## V. What The Project Is Actually Building

The project should be understood first as an end-to-end pipeline:

```text
target specification
  -> finite approved library
  -> typed DAG candidate search
  -> semantic validation
  -> accepted program graph
  -> code generation
  -> Wasm component packaging
  -> immutable artifact storage
  -> later reuse
```

This pipeline matters more than the metaphor. If the pipeline is not legible, the rest of the vision is empty.

## VI. The Four Levels

### Level 1: Atoms

Atoms are the smallest approved local building blocks.

In the original vision these are Grain functions, but the important point is not the language choice. The important point is that the atomic layer is:

- small
- explicit
- typed
- pure by architectural policy

Purity is a platform rule, not a language theorem. Grain can express mutable structures, so the system must deliberately exclude those capabilities from atoms.

The most useful atoms are not "inert." They are connective backbone pieces: transforms, combinators, predicates, wrappers, constructors, and constants.

### Level 2: Molecules

Molecules are composed candidate programs, represented as typed directed acyclic graphs.

At this level:

- nodes are inputs, constants, or atom invocations
- edges are typed data flow
- compatibility is determined by the internal type algebra
- acceptance requires semantic validation, not just type fit

This is the main search regime of the project.

Accepted molecules that prove repeatedly useful may later be promoted into higher-order local building blocks.

In the later-stage roadmap these promoted composites are the beginning of **macromolecules**: stable, reusable intracellular structure with explicit internal reuse boundaries.

### Level 3: Cells

A cell is a packaged Wasm component.

Its membrane is the WIT world or interface that defines what the component imports and exports. That membrane is real: it is the only legitimate way the component interacts with the outside world.

The membrane is **not** shared memory.

Boundary cost is also real. Crossing a component boundary means canonical lifting, lowering, allocation, marshalling, and adapter work. The architecture must model that honestly.

### Level 4: Ecologies

At the outer level, components are composed into larger applications, services, and deployment environments.

This is where the project starts to care about:

- capability surfaces
- deployment policy
- reuse across artifacts
- promotion of successful composites
- orchestration and rollout

In the final planned MVP, this outer layer also grows three additional ideas:

- **assemblies**: membrane-aware structures that bind multiple accepted artifacts into a larger whole
- **capability organelles**: service-oriented resources such as logging, configuration, key/value, HTTP, queues, and database-style services
- **mitochondria**: encapsulated external programs that can support the Wasm-Biotics through explicit API exchange

Even here, authority does not become ambient. External power must still enter through explicit membranes, and any later assimilation must preserve lineage.

The ecological layer is important, but it is downstream of the inner synthesis loop.

## VII. Design Invariants

The project should keep these rules fixed.

### 1. Dual chemistry is non-negotiable

Inside a cell, composition is governed by the internal local type algebra.

Between cells, composition is governed by WIT contracts plus Canonical ABI behavior.

These are different laws for different layers.

### 2. Atoms are pure by policy

Atoms do not perform host I/O, read clocks, mutate hidden state, or smuggle in authority.

State begins at explicit boundaries, through resources, or in external systems.

### 3. Types constrain shape, not meaning

A well-typed candidate is not automatically a correct candidate.

The system therefore needs semantic evidence:

- examples
- property checks
- policy checks
- cost checks
- provenance and trust data when needed

### 4. Boundaries are explicit and costly

Cross-component composition should never be described as free by default.

The honest boundary cost includes:

- flattening work
- allocation work
- encoding or transcoding
- adapter work
- boundary-crossing latency

### 5. Identity is intentionally split

The public compatibility identity of an artifact is its interface identity: package, version, and world or interface.

The exact implementation identity is the content identity: digest, graph, emitted interface, and build fingerprint.

The project should keep those separate:

- **species** = public compatibility identity
- **isotope** = exact built artifact identity

### 6. State must be localized, not denied

The pure-core layer is stateless.

But the broader system can and should contain stateful elements. State belongs in:

- component-private runtime state
- explicit resources
- durable external systems

The invariant is not "all state is external." The invariant is "state must be explicit and localized."

### 7. The Cloud Chamber is an observer

The Cloud Chamber is a debugger and visualization surface for synthesis.

It is not the runtime, not the deployment environment, and not the execution substrate.

### 8. External power enters through membranes

Future organelles, services, or mitochondria may support the system only through explicit WIT/resource boundaries.

If later work internalizes repeated external behavior into native structure, the resulting artifacts must preserve provenance and keep authority-bearing behavior membrane-mediated.

## VIII. Near-Term Project Direction

To make the project accessible and coherent, the work should be staged in this order.

### 1. Prove local chemistry first

Start with a small artificial universe:

- a bounded approved atom library
- a simple internal type algebra
- typed DAG composition
- semantic validation
- artifact hashing and storage

This gives the project a concrete first claim: **we can discover correct small programs in a bounded typed search space**.

### 2. Add packaging honestly

Once the local synthesis loop is reliable, wrap accepted programs as Wasm components.

At that point the project can make a second claim: **accepted programs can be exposed through explicit contracts and reused as real deployable artifacts**.

### 3. Reuse accepted artifacts as building blocks

Successful molecules should be promotable back into the searchable library as composite atoms.

This gives the project cumulative structure instead of one-off discoveries.

### 4. Treat evolution as a later control plane

Population search, mutation, lineage, and ecological selection are follow-on layers.

They are important, but they are not the core identity of Wasm-Biotic. They become meaningful only after the basic synthesis, validation, packaging, and reuse loop is understandable.

### 5. Final growth frontier

The final planned stage of the project is not open-ended mutation in the abstract.

It is a disciplined capability-growth loop:

- accepted molecules promote into macromolecules
- macromolecules and cells bind into assemblies
- assemblies gain service-I/O organelles through explicit membranes
- encapsulated external "mitochondria" may support the system through API exchange
- repeated mitochondrial behavior may later be assimilated into new native reusable structure with preserved lineage

## IX. Sandbox v0

The first sandbox should model only the local regime.

Trying to combine local synthesis, component boundaries, deployment orchestration, and open-ended evolution in one first system will make the project harder to explain and harder to verify.

### A. Starter atom library

The first atom set should stay deliberately small:

- control atoms: `logic.id`, `logic.not`, `logic.and`, `logic.or`
- backbone atoms: `seq.map`, `seq.filter`, `seq.fold`, `seq.concat`
- scalar atoms: `num.add`, `num.sub`, `num.mul`, `num.div`
- wrapper atoms: `option.default`, `option.map`, `result.default`, `result.map`
- seed atoms: `const.true`, `const.false`, `const.zero`, `const.empty`

The point is not completeness. The point is a legible search space.

### B. Internal type algebra

For the local regime, use a simplified internal algebra:

- `N`
- `B`
- `S`
- `Seq<T>`
- `Opt<T>`
- `Res<T,E>`
- `Pair<A,B>`

This is the local chemistry algebra. It is not the same thing as WIT.

### C. Bond law

For v0, keep the rule strict:

- a bond forms only when an output port unifies with an input port
- adapters are not part of the first universe
- capabilities do not enter until the component layer

This keeps the early system understandable.

### D. Candidate geometry

Treat molecules as typed directed graphs.

- chains are pipelines
- branches are fan-out or fan-in compositions
- recursion is a temporal behavior problem, not a static graph shape

### E. Cloud Chamber behavior

At each tick:

1. atoms or partial graphs are considered for expansion
2. compatible edges are proposed
3. type unification accepts or rejects the proposal
4. closed candidates are compiled into an internal artifact form
5. semantic tests score them
6. accepted candidates are stored and may be promoted for reuse

The chamber visualizes this process. It does not replace it.

### F. Thermodynamics

Temperature should describe search behavior, not runtime magic.

- high temperature means more exploration
- low temperature means more commitment to previously successful structures
- bond energy should reward type fit and semantic success while penalizing composition cost

## X. Bottom-Line Position

The Wasm-Biotic Paradigm should be presented as a concrete architectural direction:

- build programs from a finite approved library
- represent candidates as typed DAGs
- require semantic validation before acceptance
- package accepted outputs as Wasm components
- keep interfaces explicit and boundary costs honest
- store artifacts immutably with separate compatibility and content identity
- let reuse and later evolutionary search build on top of that foundation

That is a clearer and more accessible direction than leading with ontology alone. The biology metaphor can still help, but the project should now read as a disciplined systems effort first.
