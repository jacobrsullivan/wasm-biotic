# Acceptance Spec: `supervisor-approval-resume-via-operator-surface`

This scenario validates approval handling through the local operator surface.

Expected behavior:

- a local run can enter `awaiting approval`,
- the HTTP operator surface can grant that approval,
- the run completes under the same approval semantics as the kernel,
- and the resulting approval lineage remains visible in the exported read model.
