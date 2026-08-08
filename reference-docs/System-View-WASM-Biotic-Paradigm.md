# System View: Wasm-Biotic Paradigm

## I. Purpose

This document restates the Wasm-Biotic Paradigm in standard systems vocabulary.
The biology metaphor remains useful as a framing device, but it is not the normative language of the architecture.

The primary system terms are:

- finite typed component library
- typed DAG IR
- enumerative/beam synthesis
- semantic validation
- code generation
- Wasm component packaging
- artifact identity and storage

The core directional claim remains the same: software should change by synthesizing new compatible artifacts, validating them, and adopting them through explicit interfaces, rather than by mutating old artifacts in place.

---

## II. Framing Translation

The metaphor is still useful if it stays subordinate to the system model.

| Metaphor | System-view term | Meaning |
|----------|------------------|---------|
| atom | library entry | A small approved typed building block used during synthesis |
| molecule | typed DAG IR instance | A candidate composed program |
| macromolecule | promoted higher-order composite | A reusable structure built from accepted molecules or composites |
| cloud chamber | synthesis/observer environment | A visual debugger for search, scoring, and acceptance |
| cell | Wasm component | A packaged unit with an explicit interface boundary |
| assembly | membrane-aware composition | A larger unit that binds accepted artifacts across explicit boundaries |
| membrane | WIT world/interface | The import/export contract of a component |
| organelle | capability-bearing resource | An explicit stateful or service-facing resource behind a boundary |
| mitochondrion | encapsulated symbiont | A foreign program that supports the system through governed API exchange |
| fossilization | artifact storage | Recording accepted outputs as immutable artifacts |
| species / isotope | interface identity / content identity | Public compatibility identity vs exact built artifact identity |

The standard terms above define the architecture. The metaphor only helps explain why the pieces fit together.

---

## III. Architectural Thesis

The Wasm-Biotic Paradigm is an end-to-end pipeline for discovering, validating, packaging, and storing typed computational artifacts.

It has two different composition regimes:

- Local composition inside the synthesis substrate uses a typed function algebra and a typed DAG IR. In the original conceptual stack, this is the Grain-level chemistry inside the cell.
- Cross-component composition uses WIT worlds/interfaces and Wasm component boundaries.

These regimes must not be collapsed into one rule. Local compatibility is about typed graph construction. Boundary compatibility is about imports, exports, versioning, and Canonical ABI behavior.

---

## IV. Core System Model

### 1. Finite typed component library

The system begins from a bounded, explicit library of approved building blocks available at synthesis time.

- The library is finite for any given synthesis run.
- Each entry has a typed schema and a stable identity.
- In the original framing, these are the "atoms" of the system, typically realized as pure Grain-level building blocks inside a component.
- Purity for local building blocks is a platform rule, not a language guarantee.
- Previously accepted composites may be promoted back into the library as reusable entries.

This term is intentionally broader than "function list." The library is the finite searchable catalog from which candidate programs are assembled.

### 2. Typed DAG IR

The synthesis target is a typed directed acyclic graph.

- Nodes represent inputs, constants, or library-entry invocations.
- Edges represent typed data flow.
- The graph is fully typed before acceptance.
- The graph is the canonical internal representation for interpretation, hashing, scoring, explanation, and lowering.

This IR is the system's main intermediate form. It is the place where structure becomes explicit enough to search, validate, and later package.

### 3. Enumerative/beam synthesis

Search constructs candidate typed DAGs from the finite library.

- Enumerative expansion proposes graph growth steps.
- Type compatibility rejects impossible continuations early.
- Beam search keeps only the most promising partial candidates under a bounded budget.
- Ranking can include fit, simplicity, reuse value, predicted cost, and trust signals.

In the metaphor, this is where the cloud chamber imagery belongs: not as an execution substrate, but as a way to visualize search, proposal, pruning, and acceptance.

### 4. Semantic validation

Types constrain shape, not meaning. A well-typed graph is not automatically the right graph.

The system therefore requires semantic validation beyond type checking:

- example-based validation
- property-based validation
- policy checks
- cost checks
- provenance and trust checks when needed

Acceptance requires semantic evidence, not just syntactic fit. This is the stage that turns a merely valid graph into a defensible artifact.

### 5. Code generation

Accepted typed DAGs are lowered into generated implementation artifacts.

- Code generation translates the accepted IR into executable guest code.
- Interface descriptions are generated alongside implementation code where appropriate.
- Generated outputs may include manifests, observer metadata, and explanatory traces in addition to source and binaries.

Code generation is downstream of validation. The system does not treat compilation as the search mechanism.

### 6. Wasm component packaging

Generated outputs are packaged as Wasm components with explicit WIT-described boundaries.

- The membrane is the import/export contract, not raw memory exposure.
- Pure packaged artifacts can be zero-import components.
- Stateful packaged artifacts should expose or consume explicit WIT resources rather than smuggling state through hidden channels.
- Cross-boundary cost is real: canonical lift/lower, allocation, marshalling, and adapter work all matter.

This is where the local synthesis result becomes an inter-component unit.

### 7. Artifact identity and storage

Accepted artifacts are immutable outputs recorded in a store with separate compatibility and content identities.

- Interface identity captures public compatibility: package, version, and world/interface.
- Content identity captures the exact built artifact: graph, generated interface, build fingerprint, and resulting binary or digest.
- Storage should retain the IR, manifests, validation evidence, and packaged outputs.
- A local content-addressed store is sufficient for the core model; broader distribution can remain a later concern.

The architecture depends on keeping interface identity and content identity separate. Compatibility is not the same thing as byte-for-byte sameness.

### 8. Identity and versioning rules

The system should define identity and versioning explicitly rather than leaving them implicit in code or metaphor.

- Species identity is `package@version/world`.
- Semantic identity is the canonical DAG hash recorded as `graph_hash`.
- Build identity is the full `BuildFingerprint`.
- Isotope identity is `species + content_hash`, where `content_hash` is derived from canonical graph JSON, emitted WIT, and build fingerprint.
- `manifest_version` tracks manifest schema shape.
- `identity_version` tracks the isotope-hash recipe.

Short composite aliases of the form `package@version` may remain a compatibility input when they resolve to exactly one world, but the canonical displayed and documented alias is always `package@version/world`.

---

## V. Dual-Chemistry Invariant

The original document's strongest idea is still correct: there are two distinct "chemistries."

### Local chemistry

This is the synthesis domain:

- finite typed component library
- typed DAG IR
- enumerative/beam synthesis
- semantic validation

In the source paradigm, this is the intracellular regime: Grain-level local composition under the platform's purity policy.

The goal here is to discover correct closed graphs.

### Boundary chemistry

This is the component domain:

- WIT worlds/interfaces
- Canonical ABI behavior
- runtime linking and instantiation
- capability exposure through imports, exports, and resources

In the source paradigm, this is the intercellular regime: Wasm components interacting only through explicit WIT boundaries.

The goal here is to package and compose accepted artifacts honestly across boundaries.

The boundary tax must be modeled explicitly. A system-view document should never imply zero-copy or zero-cost inter-component composition by default.

---

## VI. End-to-End Flow

```text
target specification
  -> finite typed component library
  -> enumerative/beam synthesis
  -> typed DAG IR candidates
  -> semantic validation
  -> accepted typed DAG
  -> code generation
  -> Wasm component packaging
  -> artifact identity and storage
  -> runtime reuse and later composition
```

Two feedback loops matter:

- Accepted artifacts can be reintroduced into the finite typed component library as reusable composites.
- Accepted artifacts can also be promoted into higher-order macromolecules and assembly templates for later epochs.
- Observer data from search and validation can refine ranking, policies, and future library curation.
- Observer data from capability use and symbiotic exchange can later drive assimilation of external behavior into native abstractions.

---

## VII. Design Invariants

### 1. Standard vocabulary is primary

The architecture should be described in terms of libraries, IR, synthesis, validation, packaging, and storage. Metaphor is explanatory only.

### 2. The search space is explicitly bounded

For any run, synthesis operates over a finite typed component library under a bounded search strategy.

### 3. Purity is enforced by policy

Local building blocks are treated as pure because the platform constrains them to be so. This is an architectural rule, not a free property of the implementation language.

### 4. Typed DAG IR precedes packaging

The system first finds and validates a closed graph. Packaging into a Wasm component comes after acceptance, not during graph search.

### 5. Semantic validation is mandatory

Type correctness alone is insufficient. Acceptance always requires semantic evidence.

### 6. Boundary costs are real

Wasm component packaging introduces explicit ABI and adaptation costs that must be modeled honestly.

### 7. Identity is split on purpose

Public compatibility identity and exact build identity must remain distinct in storage, manifests, and reasoning.

### 8. The cloud chamber is not the runtime

The cloud chamber is the observer and debugger for synthesis. It is not the execution substrate and not the deployment model.

---

## VIII. Later-Stage Organic Growth

The final planned growth frontier extends the current model in four specific ways.

First, accepted artifacts stop being only "composites in the library." The system gains hierarchical tiers: molecules can become macromolecules, and larger membrane-aware assemblies can be constructed from accepted artifacts without erasing lineage.

Second, service-oriented I/O becomes part of the architecture through capability organelles. These are explicit WIT resources for logging, configuration, key/value services, HTTP or RPC, queues, secrets, and database-style access. They are governed by authority envelopes, not ambient host power.

Third, the ecosystem may admit `mitochondria`: encapsulated foreign programs that supply useful power through explicit API exchange. These are not magical plugins. They are symbionts with manifests, authority bounds, replay harnesses, and supervision.

Fourth, repeated successful mitochondria usage may later be assimilated into native reusable abstractions. That assimilation still preserves provenance and keeps any authority-bearing behavior membrane-mediated.

## IX. Bottom-Line Position

The Wasm-Biotic Paradigm is best understood not as a manifesto about biological software, but as a concrete system architecture:

- a finite typed component library defines the searchable building blocks
- a typed DAG IR defines the candidate program space
- enumerative/beam synthesis explores that space
- semantic validation determines acceptance
- code generation lowers accepted graphs
- Wasm component packaging gives them explicit deployable boundaries
- artifact identity and storage preserve compatibility, provenance, and reuse

The metaphor still helps explain the design direction. The system itself should be specified, implemented, and evaluated in the standard terms above.
