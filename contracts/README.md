# Contracts

This folder is reserved for frozen conceptual contracts and later concrete contract manifests.

The current compatibility anchor remains [RC-01-contract-freeze.md](RC-01-contract-freeze.md), with the carried `RC-02` through `RC-05` behavior preserved in standalone `aiaf-v1` while replay, orchestration, governance, challenger evaluation, promotion, and bounded `v1` completion capabilities broaden around the fixed interface.

The Phase D local-first pre-federation exchange layer now also carries an explicit `PD-01` contract-anchor family:

- [PD-01-phase-d-anchor-family.md](PD-01-phase-d-anchor-family.md)
- [PD-01-phase-d-anchor-family.json](PD-01-phase-d-anchor-family.json)
- [PD-01-factory-identity-manifest-anchor.md](PD-01-factory-identity-manifest-anchor.md)
- [PD-01-exchange-envelope-anchor.md](PD-01-exchange-envelope-anchor.md)
- [PD-01-compatibility-decision-anchor.md](PD-01-compatibility-decision-anchor.md)
- [PD-01-import-quarantine-anchor.md](PD-01-import-quarantine-anchor.md)
- [PD-02-phase-d-contract-manifest-anchor.md](PD-02-phase-d-contract-manifest-anchor.md)
- [PD-02-phase-d-contract-manifest-anchor.json](PD-02-phase-d-contract-manifest-anchor.json)

In the live root package today, the active compatibility surface is still the carried Rust `aiaf_v1::execution` API plus the conceptual contract files in this directory. The repository does not yet ship separate live WIT/component contract manifests as a first-class root surface.
