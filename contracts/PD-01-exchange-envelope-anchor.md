# PD-01 Exchange Envelope Anchor

## 1. Purpose

This anchor freezes the minimum conceptual semantics for the Phase D exchange envelope.

## 2. Frozen Field Set

The exchange envelope must carry:

- `exchange_id`
- `sender_identity_ref`
- `receiver_scope_ref`
- `packet_class`
- `payload_refs`
- `trust_requirements`
- `rollback_requirements`

## 3. Frozen Packet Taxonomy

The permitted Phase D packet classes are:

- lineage import
- evidence exchange
- compatibility statement
- memory exchange

## 4. Frozen Rules

- no payload moves without an exchange envelope
- no envelope omits `rollback_requirements`
- no envelope omits `trust_requirements`
- the receiver scope remains explicit and bounded
