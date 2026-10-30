# Historical component-complete test inputs

These files are exact, small inputs retained so ordinary source checkouts can
run tests that bind current code to historical R1 evidence:

- `2026-08-02-adversarial-isolation.v1.json` is the closed adversarial report;
- `sha256-99c226f2...json` is the certified native TCB inventory named by that
  report; and
- `capability-router-component.wasm` is the exact component exercised by the
  report, retained because recompiling current source does not recreate its
  historical digest.

They are test fixtures, not a substitute for the complete content-addressed
R1 package or R4 custody trees. Their bytes came from the retained release
artifacts; the test verifies the inventory against its declared SHA-256 digest.
