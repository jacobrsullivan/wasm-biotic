# **Design Memo: Wasm-Biotic Evolution Engine**

## **1\. Purpose**

This memo describes a **later-stage direction** for Wasm-Biotic, not the foundational definition of the project.

The core project still begins with a legible synthesis loop:

* finite approved library  
* typed DAG candidate search  
* semantic validation  
* Wasm component packaging  
* immutable artifact storage and reuse

The Wasm-Biotic Evolution Engine sits **on top of that substrate** as an orchestration layer that continuously discovers, evaluates, and promotes better Wasm-Biotic artifacts under explicit architectural laws.

It exists to answer one serious question:

**Can a typed, immutable artifact ecosystem accumulate useful computational structure over generations without collapsing into unreadable self-modifying sludge?**

The answer is “possibly,” but only if the engine keeps the current Wasm-Biotic invariants intact: bounded search, typed DAGs before packaging, semantic validation before acceptance, explicit component boundaries, and split compatibility/content identity.

## **2\. Thesis**

This design only makes sense if the base Wasm-Biotic pipeline stays intact and authoritative.

The engine combines three things:

* **Wasm-Biotic** as the substrate for heredity, embodiment, identity, and replayability.  
* **Autoresearch-style looping** as the experiment protocol.  
* **Evolutionary search** as the global exploration mechanism.

In practice:

* the **genotype** is a typed DAG plus configuration and packaging choices,  
* the **phenotype** is the executable Wasm component or engine resource,  
* the **environment** is the benchmark, policy, and cost regime,  
* the **selection rule** is semantic correctness first, then multi-objective ranking.

That matches the structure you already have: target spec, finite library, typed DAG candidates, semantic validation, codegen, Wasm packaging, and fossilization into a store with species/isotope identity.

The important framing point is this: the engine is a way to search over artifact candidates more aggressively, not a license to blur the underlying architectural rules.

## **3\. Non-goals**

This engine should **not**:

* mutate arbitrary source trees,  
* treat LLM output as truth,  
* optimize only for one scalar metric,  
* erase provenance,  
* let interface changes happen casually,  
* blur the local typed-graph regime with the component-boundary regime,  
* become the shorthand explanation for what the whole project is.

WIT defines contracts, not behavior, and worlds define strict import/export boundaries. Resources are explicit handles to stateful functionality that exists on one side of a component boundary. That means state, authority, and cross-boundary costs must stay explicit. ([component-model.bytecodealliance.org](https://component-model.bytecodealliance.org/design/wit.html?utm_source=chatgpt.com))

## **4\. Architectural position**

The Evolution Engine is **not** a replacement for the current synthesis engine. It is a control plane over it.

The current stack already has the pieces it needs to stand on: a bounded atom library, typed DAG IR, beam search chamber, semantic harness, codegen, runtime, store, registry, and observer. That is exactly the right substrate.

If that substrate is confusing, the evolution layer will only make the project harder to understand. So the correct order is:

1. make the base synthesis pipeline understandable  
2. make artifact packaging and identity reliable  
3. add evolutionary orchestration as a higher-level layer

The new engine adds five capabilities:

1. population management  
2. mutation and recombination  
3. multi-objective evaluation  
4. lineage and archive management  
5. promotion and curation policies

## **5\. Core architecture**

### **5.1 Layers**

**Layer A — Stable substrate**  
Keep the current Wasm-Biotic pipeline intact: registry snapshot, monomorphization, composite resolution, beam search, semantic harness, flattening, codegen, packaging, runtime, store.

**Layer B — Evolution manager**  
A new orchestration service that chooses parents, applies operators, launches evaluations, records lineage, and promotes winners.

**Layer C — Research operator layer**  
Optional LLM agents propose candidate mutations, new tests, or ranking-policy tweaks. They do not validate artifacts. Karpathy’s repo is useful here because it shows the value of a narrow experiment loop with lightweight “research-org code” in `program.md`, a single editable surface, a fixed wall-clock budget, and a comparable validation metric. ([GitHub](https://github.com/karpathy/autoresearch))

**Layer D — Ecological runtime**  
Different deployment contexts select for different winners: low latency, low boundary tax, low memory use, high reuse value, strong explainability, or robust stateful behavior.

### **5.2 Main runtime objects**

**Library snapshot**  
The finite searchable catalog for a run. Includes primitive atoms and selected composite atoms, and later may include accepted macromolecules, assembly templates, organelle descriptors, and adapter species that are already inside the active policy envelope. It must remain finite and versioned.

**Genome**  
A candidate artifact specification:

* species target  
* typed DAG  
* artifact tier  
* atom/composite references  
* constant values  
* packaging mode  
* evaluator policy version  
* optional resource/world choices  
* optional assembly plan  
* optional capability envelope  
* optional mitochondria references  
* parent references

**Phenotype record**  
The built and evaluated realization:

* flattened graph  
* emitted WIT  
* compiled component  
* runtime traces  
* semantic results  
* cost vector  
* capability diff  
* replay bundle  
* observer bundle

**Population**  
The active set of candidates for one species or one ecology.

**Archive**  
Persistent elite set plus novelty set plus promoted composite set.

**Assembly record**  
A membrane-aware composition plan that binds accepted artifacts into a larger replayable unit with explicit partition, boundary-cost, and authority metadata.

**Capability organelle**  
An explicit resource-facing artifact that exposes service-oriented I/O through a capability-bearing membrane.

**Mitochondrion manifest**  
A governed record for an encapsulated non-native program, including contract, authority envelope, health signals, and provenance.

**Ecosystem epoch**  
The snapshot boundary that defines which promoted artifacts are visible to a run or generation.

**Lineage graph**  
Parent-child relationships across generations, with mutation metadata and acceptance outcome.

## **6\. Representation model**

### **6.1 Genotype**

The genotype should be explicit and minimal:

* `species_id`  
* `world_id`  
* `genome_version`  
* `artifact_tier`  
* `surface_graph`  
* `flattened_graph_hash`  
* `allowed_atoms_snapshot`  
* `packaging_profile`  
* `eval_policy_version`  
* `assembly_plan`  
* `capability_envelope`  
* `epoch_id`  
* `mitochondria_refs`  
* `parent_ids`  
* `operator_trace`

The key point is this: **genotype is not source code text**. It is structured artifact intent.

### **6.2 Phenotype**

The phenotype is the executable output plus measurements:

* `component.wasm`  
* optional `engine` resource package  
* WIT package  
* manifest  
* scorecard  
* trace summary  
* runtime error profile  
* boundary-cost measurements  
* capability-diff summary  
* replay bundle  
* rollback handle

Wasmtime compiles a component up front through `Component::new`, and typed component calls copy/lower parameters into WebAssembly memory as needed, can trap, and can fail on canonical-ABI violations. That is exactly why packaging and boundary costs belong in fitness. ([Wasmtime](https://docs.wasmtime.dev/api/wasmtime/component/struct.Component.html?utm_source=chatgpt.com))

### **6.3 Species model**

A **species** is the compatibility contract: `package@version/world`.  
An **isotope** is the exact implementation: species plus content hash.  
A **semantic identity** is the canonical DAG hash.  
A **build identity** is the build fingerprint.

This split is non-negotiable. It is what makes evolution replayable instead of mystical.

## **7\. End-to-end execution flow**

The Evolution Engine should run this loop:

1. choose target species and ecology  
2. build finite registry snapshot  
3. initialize or load population  
4. select parents from archive/population  
5. apply one mutation or recombination operator  
6. run static legality checks  
7. evaluate surface graph in local chamber  
8. run semantic harness  
9. flatten and package only if accepted by local gates  
10. compile component / engine resource  
11. run runtime and differential tests  
12. compute full fitness vector  
13. update lineage store  
14. either reject, retain in niche, or promote  
15. optionally promote offspring across the correct tier  
16. roll accepted promotions into the next ecosystem epoch or later run snapshot

That fits the current Wasm-Biotic sequencing: graph first, packaging after acceptance, store after build, reuse through finite snapshots after fossilization.

## **8\. Mutation operators**

These should be structured and type-aware.

### **8.1 Safe local mutations**

These are the default operators for MVP-1:

* replace an atom with a type-compatible sibling  
* retune a constant  
* insert a compatible adapter/combinator  
* delete a dead or redundant node  
* reorder commutative inputs into canonical form  
* replace primitive subgraph with an equivalent composite  
* inline a composite back to primitive form  
* switch packaging profile from pure component to engine resource where allowed

These preserve legibility and let the type system do most of the pruning.

### **8.2 Structural graph mutations**

Use only after safe local mutation works:

* splice in a previously successful subgraph  
* collapse repeated motif into candidate composite  
* expand one subgraph into two-step alternative  
* reroute one input path through a guard or wrapper  
* split a molecule into staged subgraphs for future packaging tests

### **8.3 Recombination**

Recombination is dangerous unless constrained. Only allow it when parents share:

* species  
* compatible signature  
* compatible world  
* compatible evaluation regime

Allowed recombinations:

* subgraph crossover at typed cut points  
* elite-subroutine grafting  
* packaging-profile swap  
* parameter block crossover

Do **not** do raw random graph crossover. It produces junk.

### **8.4 Boundary mutations**

This is later-stage evolution, not MVP-1:

* pure component ↔ resource-backed engine  
* import minimization  
* world narrowing  
* capability accretion through explicit world inclusion  
* repartitioning large artifacts into component pairs  
* fusion of over-partitioned components

WIT worlds define strict import/export boundaries, and resources exist specifically to localize non-copyable state behind those boundaries. That makes boundary evolution meaningful but also high-risk. ([component-model.bytecodealliance.org](https://component-model.bytecodealliance.org/design/worlds.html?utm_source=chatgpt.com))

## **9\. Fitness model**

This is where most systems go wrong.

Do **not** collapse everything into one metric too early.

### **9.1 Hard gates first**

A candidate is dead on arrival if it fails any of these:

* type legality  
* arity/schema legality  
* semantic examples  
* required property checks  
* policy constraints  
* provenance rules  
* differential equivalence where required  
* packaging validity  
* runtime safety/ABI validity

Your own system docs are right: type correctness alone is not enough; semantic validation is mandatory.

### **9.2 Multi-objective vector**

After the gates, compute a vector:

* semantic correctness  
* property robustness  
* runtime success rate  
* node count  
* allocation count  
* branch count  
* boundary tax  
* compile time  
* memory footprint  
* trace explainability  
* reuse potential  
* novelty distance  
* trust/provenance confidence

### **9.3 Suggested objective hierarchy**

Priority order:

1. correctness  
2. robustness  
3. simplicity  
4. boundary efficiency  
5. execution efficiency  
6. reuse value  
7. explainability  
8. novelty

That is the right hierarchy because correctness and robustness are existential; novelty is not.

### **9.4 Selection policy**

Use a hybrid:

* **Pareto frontier** within a species  
* **niche champions** by ecology  
* **simplicity winner** for maintainability  
* **novelty archive** for exploration  
* **production champion** for current deployment

### **9.5 Practical scalarization**

For ranking inside one niche, use a scalar score like:

score \=  
  correctness\_weighted  
  \- complexity\_penalty  
  \- boundary\_penalty  
  \- instability\_penalty  
  \+ reuse\_bonus  
  \+ novelty\_bonus\_small

But keep the underlying vector stored. Never throw it away.

## **10\. Lineage store**

This is the heart of the system.

The current store already tracks species/isotopes, artifact paths, score data, and composite registration. The evolution layer should extend that rather than inventing a parallel store.

### **10.1 Required tables**

**species**

* `species_id`  
* `package`  
* `version`  
* `world`  
* `status`  
* `policy_version`

**isotopes**

* `isotope_id`  
* `species_id`  
* `content_hash`  
* `graph_hash`  
* `build_fingerprint_hash`  
* `wit_hash`  
* `artifact_paths`  
* `created_at`

**genomes**

* `genome_id`  
* `species_id`  
* `surface_graph_json`  
* `packaging_profile`  
* `allowed_atoms_snapshot_hash`  
* `eval_policy_version`

**lineage\_edges**

* `child_genome_id`  
* `parent_genome_id`  
* `operator_type`  
* `operator_payload`  
* `generation_index`

**evaluations**

* `evaluation_id`  
* `genome_id`  
* `environment_id`  
* `gate_results`  
* `objective_vector`  
* `scalar_score`  
* `trace_bundle_path`  
* `runtime_failures`

**archives**

* `archive_id`  
* `genome_id`  
* `archive_class`  
  values: `elite`, `novelty`, `production`, `composite-candidate`, `retired`

**promotions**

* `genome_id`  
* `promoted_as_composite_species_id`  
* `promotion_reason`  
* `approved_by_policy_version`

**environments**

* `environment_id`  
* `benchmark_suite_hash`  
* `resource_budget`  
* `runtime_version`  
* `host_profile`  
* `policy_bundle_hash`

### **10.2 Why this matters**

Without lineage, you do not have evolution. You have a pile of experiments.

Without archived failures, you cannot inspect where search is wasting time.

Without environment versioning, your fitness comparisons are garbage.

## **11\. Observer and telemetry**

The observer should become an ecological dashboard, not just a search report.

Track:

* valid mutation rate  
* legal offspring rate  
* semantic pass rate  
* packaging success rate  
* runtime trap rate  
* average boundary tax  
* composite reuse frequency  
* novelty spread  
* lineage depth  
* extinction rate  
* promotion rate  
* rollback rate  
* species health score

Your own notes already point in this direction: the cloud chamber is an observer/debugger, not the runtime itself. Keep it that way.

## **12\. Role of LLM agents**

Use LLMs, but cage them.

They are useful for:

* proposing mutation families  
* proposing missing tests  
* clustering niches  
* writing human-readable explanations  
* suggesting promotion candidates  
* synthesizing search-policy variants

They are **not** useful as the acceptance authority.

Autoresearch’s best lesson is not “let the model rewrite everything.” It is “constrain the editable surface, constrain the experiment, compare against a stable metric, and iterate fast.” In that repo the agent edits only `train.py`, runs a fixed 5-minute experiment, and compares `val_bpb`; `program.md` acts as lightweight org/process code. ([GitHub](https://github.com/karpathy/autoresearch))

For Wasm-Biotic, the editable surface should be the genome and policy layer, not arbitrary repo text.

## **13\. MVP phases**

## **MVP-1 — Species-constrained isotope evolution**

**Goal:** Evolve better implementations of a fixed species without changing interface.

Scope:

* pure intracellular evolution only  
* no world changes  
* no resource mutation  
* no component partitioning changes  
* no arbitrary source edits  
* mutation over typed DAGs and parameters only

Operators:

* atom replacement  
* constant tuning  
* adapter insertion  
* dead-node removal  
* composite inlining / reuse

Fitness:

* examples  
* properties  
* node count  
* alloc count  
* branch count  
* boundary tax estimate  
* runtime equivalence

Success criteria:

* beats baseline beam-only search on at least 3 nontrivial species  
* no increase in semantic failure rate  
* lineage and replayability work end to end  
* promotion of at least one reusable composite discovered by evolution

This is the sane first build.

## **MVP-2 — Composite ecology**

**Goal:** Let accepted offspring become new building blocks.

Add:

* promotion policy  
* novelty archive  
* reuse-aware selection  
* elite subgraph grafting  
* cross-run archive persistence

Success criteria:

* search depth improves because promoted composites shorten future discoveries  
* average nodes-to-solution drops on held-out targets  
* archive remains non-bloated

This is where cumulative structure begins.

## **MVP-3 — Boundary-aware evolution**

**Goal:** Evolve packaging and state placement.

Add:

* pure component vs engine-resource phenotype choice  
* world narrowing  
* capability/accounting  
* cross-boundary measurement from actual component calls  
* interface-stable isotope optimization

Success criteria:

* better latency or lower memory through packaging choices  
* no hidden-capability regressions  
* measured boundary costs line up with expected cost model

This is where the Wasm component model becomes a real evolutionary dimension, not just a backend packaging step. Worlds and resources make that boundary explicit. ([component-model.bytecodealliance.org](https://component-model.bytecodealliance.org/design/worlds.html?utm_source=chatgpt.com))

## **MVP-4 — Organic capability growth and symbiotic substrate**

This is the final planned MVP.

Its goal is not casual open-ended mutation. Its goal is to let the ecosystem accumulate reusable structure across tiers while keeping boundaries, lineage, and authority explicit.

Scope:

* hierarchical promotion from molecules into macromolecules and assemblies  
* ecosystem epochs and finite substrate snapshots  
* service-oriented capability organelles behind WIT resources  
* policy-governed assembly binding, partitioning, and fusion  
* membrane-bound mitochondria symbiosis  
* provenance-preserving assimilation of repeated mitochondrial behavior into native reusable structure

Workstreams:

1. **Growth substrate**  
   Tier-aware archive and promotion logic, promotion evidence bundles, and finite substrate snapshots.

2. **Assembly substrate**  
   Explicit membrane-aware assembly IR with partition, repartition, fusion, and adapter-aware composition.

3. **Capability organelles**  
   Service-I/O resources for logging, configuration, key/value, secrets, HTTP/RPC, queues, and database-style services under machine-enforced authority envelopes.

4. **Mitochondria protocol**  
   Encapsulated foreign-program onboarding, adapter membranes, replay harnesses, supervision, and symbiosis scoring.

5. **Assimilation loop**  
   Motif mining, native derivative evolution, and promotion of reusable abstractions that preserve source lineage.

Success criteria:

* accepted outputs promote across tiers over multiple epochs without manual registry handoff  
* assemblies preserve replayability while surfacing measurable boundary and authority costs  
* service-I/O organelles remain explicit and capability-accounted  
* at least one mitochondrion is admitted and used symbiotically through explicit API exchange  
* at least one native abstraction is assimilated from repeated mitochondrial behavior without hiding provenance

This final MVP absorbs the old split between boundary-aware `vFuture` work and the narrower inter-species proposal flow. Those documents remain useful source material, but they are no longer the canonical roadmap labels.

## **14\. Recommended build order**

1. extend manifest/store schema for lineage  
2. build genome object and operator trace format  
3. implement safe mutation operators  
4. implement hard-gate evaluator  
5. add objective-vector scoring  
6. add population manager  
7. add archive and promotion rules  
8. add observer/ecology reports  
9. only then add recombination  
10. only then add boundary mutations  
11. add hierarchical artifact tiers and archive classes  
12. add ecosystem epochs and finite substrate snapshots  
13. add assembly IR and membrane-aware evaluation  
14. add service-oriented organelle descriptors and authority envelopes  
15. add capability-diff promotion rules and quarantine flow  
16. add mitochondria manifests, adapters, and supervision  
17. add assimilation mining and native-derivative promotion

That order keeps the system testable at each stage.

## **15\. Main risks**

### **Bloat**

Evolutionary systems love to grow garbage.

Mitigation:

* hard node caps  
* parsimony pressure  
* graph dedup  
* archive quotas  
* retirement rules

### **Metric gaming**

Agents will optimize what you measure, not what you mean.

Mitigation:

* hidden holdout evaluation  
* multiple property families  
* differential tests  
* robustness trials  
* policy checks

### **Illegible winners**

A better score is useless if nobody can trust or reuse the result.

Mitigation:

* explanation bundle  
* lineage graph  
* promotion review  
* simplicity preference within Pareto frontier

### **Boundary delusion**

It is easy to pretend component boundaries are free. They are not.

Mitigation:

* actual runtime measurements  
* separate local and boundary fitness terms  
* explicit capability accounting

Official component-model docs and Wasmtime docs are very clear that worlds are real boundaries, resources are explicit handles, and typed calls may copy data and fail during canonical-ABI lowering/lifting. ([component-model.bytecodealliance.org](https://component-model.bytecodealliance.org/design/worlds.html?utm_source=chatgpt.com))

### **Authority creep**

Once service-I/O and mitochondria exist, the easy mistake is to let useful artifacts silently accumulate more authority than their local structure justifies.

Mitigation:

* capability envelopes  
* explicit capability diffs  
* machine-enforced quarantine for envelope expansion  
* rollback handles on authority-bearing promotions

## **16\. Bottom-line recommendation**

The correct near-term posture is still to build the bounded substrate first.

But the canonical long-range destination is now clear:

**Wasm-Biotic should grow from typed, immutable, replayable molecules into macromolecules, assemblies, capability organelles, and finally membrane-bound mitochondrial symbiosis without abandoning provenance, explicit authority, or honest boundary costs.**

That is a stronger thesis than vague autonomous-software rhetoric because it keeps the hard parts visible: finite snapshots, promotion policy, capability accounting, and replayable adoption.

The next useful step is the dedicated `MVP-4` implementation guide in [EvoEngine-MVP-4-Organic-Capability-Growth-And-Symbiotic-Substrate.md](/Users/jacobsullivan/Desktop/wasm-biotic/design-and-planning/EvoEngine-MVP-4-Organic-Capability-Growth-And-Symbiotic-Substrate.md).
