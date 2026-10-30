# Independent substrate regression fixtures

`r1/manifest.json` and `r1/substrate-profile.json` are exact canonical
documents copied from the retained R1 package. They are the only historical
package bytes needed by the source-only parser regression test.

The complete R1 package—including its components, certificates and
evidence—remains external content-addressed custody material. Substrate unit
tests use a purpose-built in-memory release instead of silently depending on
that 18 MiB tree.
