# Supervisor Promote Activate Successor Campaign

This is the carried `RC-04` integrated acceptance scenario inside standalone `aiaf-v1`.

It proves that:

- a `promotion-ready` native challenger can become a governed `promotion act`
- epoch adoption is explicit, artifact-backed, and tied to the next incumbent session
- the promoted incumbent can start one bounded successor-shaping campaign in the next epoch
- successor-loop comparison evidence can be produced without interface mutation
- quarantine, reversal-window evaluation, and rollback remain available after activation

Standalone `aiaf-v1` keeps this scenario as a standing regression gate, and it passes only when all of the following are true:

- the promotion act starts from a `Promotable` decision backed by comparison, review, and rollback evidence
- the next-epoch incumbent is activated through an explicit epoch handoff checkpoint
- the promoted incumbent completes a bounded successor-shaping campaign using governed control surfaces
- a durable `PromotionActivationBundle` can be written and loaded without loss
- a post-activation governance problem can trigger reversal-window evaluation and rollback to the pre-promotion incumbent snapshot

Implementation:

- [supervisor_promote_activate_successor_campaign.rs](supervisor_promote_activate_successor_campaign.rs)
