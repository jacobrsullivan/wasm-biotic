# PD-01 Factory Identity Manifest Anchor

## 1. Purpose

This anchor freezes the minimum conceptual semantics for the Phase D factory identity manifest.

## 2. Frozen Field Set

The identity manifest must carry:

- `factory_identity_id`
- `factory_ref`
- `contract_refs`
- `service_closure_refs`
- `governance_policy_refs`
- `lineage_root_ref`
- `claim_boundary`
- `summary`

## 3. Frozen Rules

- no inter-factory packet without a sender identity manifest
- the identity manifest must state a bounded `claim_boundary`
- the manifest does not grant ambient trust by repo proximity or machine locality
- the manifest identifies a bounded local-first ecosystem participant only

## 4. Claim Boundary

The identity manifest may describe one bounded local-first ecosystem participant.

It may not imply federation, remote orchestration, or autonomous ecosystem trust.
