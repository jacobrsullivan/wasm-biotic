# Closure evaluator component

This pure policy package decides whether a bounded local factory dossier is
complete. The native host only resolves the content-addressed dossier and
stores the returned decision bytes.

The evaluator requires exact digests for the graph manifest, native TCB and six
independent evidence classes: graph validation, native-boundary audit, complete
cycle, restart recovery, adversarial isolation and successor cycle. A valid but
incomplete dossier produces a truthful `not-yet` decision with named blockers;
malformed or schema-unknown input fails closed.

This decision is deliberately scoped to component-complete architecture. It
does not manufacture external qualification or publication evidence.
