This scenario validates the `v2.3` checkpoint, replay, and recovery topology surfaces.

It proves that:
- checkpoint and replay are treated as runtime topology rather than storage-only helpers,
- bounded recovery remains attributable to runtime state,
- and later governance lines can consume a tested replay/recovery baseline.
