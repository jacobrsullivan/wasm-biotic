AIAF is an AI system built on the idea that software should improve by growing new, tested parts rather than by endlessly patching one large opaque program in place. It is part of the Wasm-Biotic vision: software built from small, trusted WebAssembly components that can be combined into increasingly capable systems. The long-term goal is for AIAF itself to be composed of these same parts, so that the  entire ecosystem around the language model moves toward a safe, governed form of self-improvement, and ultimately self-replication, in which each new candidate version is generated, tested, and reviewed.

In its current form, AIAF is a local control-plane and evidence prototype for
controlled upgrade experiments. It can persist governed sessions, approvals,
checkpoints, quarantine, and evidence, and it can build and execute a narrow
class of WebAssembly components. Its broader candidate, worker, service,
factory, and ecosystem paths are deterministic rehearsals today: they create
inspectable comparison, lineage, approval, and rollback-reference records, but
they do not yet perform the complete advertised real-world lifecycle.

AIAF is building workspace services for reading and changing code in controlled environments, execution services for running builds, tests, and transformations, memory services for retrieving the right prior context and preserving verified history, worker-coordination services for dispatching specialist components and combining their results, approval and scheduling services for managing risky or long-running work, review and promotion services for deciding what should replace the current system, and infrastructure services such as logging, configuration, queues, storage, secrets, and network connectors. Together, these pieces are meant to make AIAF not just an AI assistant, but a WebAssembly-native harness for producing, evaluating, and governing software changes of legacy code and wasm-biotic systems. 

Core AIAF reference anchors:

- [AIAF Self-Hosting Thesis](./AIAF-Self-Hosting-Thesis.md)
- [AIAF NorthStar Inspiration](./AIAF-NorthStar-Inspiration.md)
