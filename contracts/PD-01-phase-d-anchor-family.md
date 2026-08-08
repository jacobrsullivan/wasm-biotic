# PD-01 Phase D Contract-Anchor Family

Status: Active conceptual anchor  
Applies to: Phase D local-first pre-federation exchange surfaces  
Primary references:
- [AIAF Phase D Implementation Roadmap and Guide](../design-and-planning/AI-Agent-Factory/AIAF-phase-d-implementation-roadmap-and-guide.md)
- [Phase D Workstream A](../design-and-planning/AI-Agent-Factory/phase-d/Workstream-A-technical-design.md)
- [Phase D Workstream D](../design-and-planning/AI-Agent-Factory/phase-d/Workstream-D-technical-design.md)

## 1. Purpose

This document freezes the first explicit contract-anchor family for Phase D.

Its job is to keep the new inter-factory semantics grounded in explicit repo artifacts rather than leaving them only in planning prose.

## 2. Anchor Family

The `PD-01` family contains four contract anchors:

- `identity_anchor_ref`: [PD-01-factory-identity-manifest-anchor.md](./PD-01-factory-identity-manifest-anchor.md)
- `exchange_anchor_ref`: [PD-01-exchange-envelope-anchor.md](./PD-01-exchange-envelope-anchor.md)
- `compatibility_anchor_ref`: [PD-01-compatibility-decision-anchor.md](./PD-01-compatibility-decision-anchor.md)
- `quarantine_anchor_ref`: [PD-01-import-quarantine-anchor.md](./PD-01-import-quarantine-anchor.md)

## 3. Version Commitments

The `version_refs` for this family are:

- `phase-d-local-first`
- `phase-d-pre-federation`
- `phase-d-quarantine-first`
- `phase-d-bounded-memory-exchange`

These commitments mean:

- packet exchange remains local-first,
- Phase D remains pre-federation,
- imported packets begin quarantined,
- and memory exchange remains bounded and pointer-driven.

## 4. Boundary Statement

`PD-01` allows the project to say:

- bounded factories can exchange typed, attributable, quarantine-capable packets under explicit compatibility law.

`PD-01` does not allow the project to say:

- federation exists,
- remote orchestration exists,
- or ecosystem autonomy is solved.

## 5. Usage Rule

Any new operator dossier, import decision surface, or future ecosystem packet surface that relies on Phase D semantics should cite the relevant `PD-01` anchors rather than redefining those meanings informally.
