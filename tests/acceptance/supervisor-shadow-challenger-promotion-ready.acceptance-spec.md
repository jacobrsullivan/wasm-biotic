# Supervisor Shadow Challenger Promotion Ready

This is the carried `RC-03` integrated acceptance scenario inside standalone `aiaf-v1`.

It proves that:

- a native challenger supervisor can be evaluated against the same shared inputs as an incumbent
- native control-plane capability worlds are sufficient for bounded challenger operation
- challenger evaluation remains replayable and rollback-safe
- the system can produce a governed generation comparison record
- the system can end in a `promotion-ready` decision state before live promotion begins

Standalone `aiaf-v1` keeps this scenario as a standing regression gate, and it passes only when all of the following are true:

- the challenger and incumbent use the same shared input refs
- worker dispatch stays inside native `campaign-control`, `approval-gateway`, `review-promotion`, `schedule-tick`, and `memory-access` surfaces
- a durable shadow-evaluation bundle can be written and loaded without loss
- rollback restores the challenger to an earlier checkpoint snapshot
- the final decision is `Promotable`, but the scenario itself does not perform live promotion

Implementation:

- [supervisor_shadow_challenger_promotion_ready.rs](supervisor_shadow_challenger_promotion_ready.rs)
