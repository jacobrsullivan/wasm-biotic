# PD-01 Compatibility Decision Anchor

## 1. Purpose

This anchor freezes the minimum conceptual semantics for Phase D compatibility decisions.

## 2. Frozen Field Set

The compatibility decision must carry:

- `decision_id`
- `exchange_ref`
- `contract_compatibility`
- `service_compatibility`
- `governance_compatibility`
- `decision`
- `summary`

## 3. Frozen Rules

- compatibility is explicit and typed
- incompatible exchange does not silently proceed
- compatibility may accept to quarantine, reject, or accept for review
- compatibility does not itself imply admission into active runtime state
