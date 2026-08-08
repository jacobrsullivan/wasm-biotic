# R4 public-only recovery guide

This procedure recovers the bounded R4 Wasm-Biotic factory from published
bytes. It uses public trust material and non-secret local capacity only. It
does not build, sign, or accept a private key.

The aggregate R4 publication may claim the bounded component-complete factory.
It does not claim the external North Star. A lifecycle report deliberately has
`component_complete_claim: false`; only the signed aggregate publication owns
that broader release claim.

Stop on every unexpected exit status or mismatch. Never weaken a check, reuse
a state directory, or replace a failed input with an unsigned local build.

## 1. Independently pin trust

Obtain these through a channel independent of the publication being checked:

- the canonical R4 generation-1 2-of-3 governance policy;
- its expected `sha256:` digest;
- the expected content-addressed publication directory name;
- the raw 32-byte Ed25519 package-certifier leaf public-key file, plus its 64
  lowercase hexadecimal rendering; and
- the expected `sha256:` key ID of those exact 32 bytes.

Also use separately obtained or locally reviewed copies of the four verifier
scripts below. Do not bootstrap verification with tools taken from an
unverified archive.

Replace every angle-bracket placeholder before running anything. A placeholder
is not evidence.

```sh
set -eu

GOVERNANCE_TOOL='<independent-path>/r4-certifier-governance.py'
PUBLICATION_TOOL='<independent-path>/r4-publication.py'
ARCHIVE_TOOL='<independent-path>/r4-install-archive.py'
POST_RECOVERY_TOOL='<independent-path>/r4-postpublication-recovery.py'
PINNED_POLICY='<independent-path>/r4-genesis-policy.json'
LEAF_PUBLIC_KEY_RAW='<independent-path>/r3-certifier-public-key.raw'
PUBLICATION='<download-root>/<sha256-publication-root-directory>'

EXPECTED_POLICY_DIGEST='<sha256:64-lowercase-hex>'
EXPECTED_PUBLICATION_DIRECTORY='<sha256-64-lowercase-hex>'
LEAF_PUBLIC_KEY_HEX='<64-lowercase-hex>'
EXPECTED_LEAF_KEY_ID='<sha256:64-lowercase-hex>'
```

Validate both pins before trusting any release object:

```sh
python3 "$GOVERNANCE_TOOL" validate-policy --genesis "$PINNED_POLICY"

ACTUAL_POLICY_DIGEST="$(
  python3 "$GOVERNANCE_TOOL" policy-digest "$PINNED_POLICY"
)"
test "$ACTUAL_POLICY_DIGEST" = "$EXPECTED_POLICY_DIGEST"

ACTUAL_LEAF_KEY_ID="$(python3 -c \
  'import hashlib,re,sys; b=open(sys.argv[1],"rb").read(); k=sys.argv[2]; assert len(b)==32 and re.fullmatch(r"[0-9a-f]{64}",k) and b.hex()==k; print("sha256:"+hashlib.sha256(b).hexdigest())' \
  "$LEAF_PUBLIC_KEY_RAW" "$LEAF_PUBLIC_KEY_HEX")"
test "$ACTUAL_LEAF_KEY_ID" = "$EXPECTED_LEAF_KEY_ID"

test "$(basename "$PUBLICATION")" = "$EXPECTED_PUBLICATION_DIRECTORY"
```

The governance pin and leaf pin are different authorities. The 2-of-3 policy
authorizes the exact R4 publication. The leaf key verifies each component
package through production admission. Neither key selects or activates a
graph.

## 2. Verify the publication

```sh
python3 "$PUBLICATION_TOOL" verify \
  --publication "$PUBLICATION" \
  --policy "$PINNED_POLICY" \
  --release-public-key "$LEAF_PUBLIC_KEY_RAW"
```

This command must report `verified`. It checks the independently pinned policy
against the embedded policy, the 2-of-3 release-domain quorum, canonical claim
and root documents, the exact file/object closure, every object digest and
mode, both closed targets, and each target's native executable/attestation
pair. The publication directory name must equal the derived publication root.

If separate publication-domain metadata was supplied, verify it as an
additional binding; it is not a substitute for the command above:

```sh
python3 "$GOVERNANCE_TOOL" verify-publication \
  --policy "$PINNED_POLICY" \
  --payload '<path>/publication-metadata-payload.json' \
  --signature '<path>/publication-signature-1.json' \
  --signature '<path>/publication-signature-2.json'
```

## 3. Select the closed host target

R4 supports exactly two native targets. Fail closed on every other host.

```sh
case "$(uname -s)/$(uname -m)" in
  Darwin/arm64) TARGET='aarch64-apple-darwin' ;;
  Linux/x86_64) TARGET='x86_64-unknown-linux-gnu' ;;
  *) echo 'host is outside the closed R4 platform set' >&2; exit 1 ;;
esac
```

From the now-verified `claim.json`, copy the exact `path` and `digest` values
for the three global archive roles and the selected target's
`native-executable` role. Do not infer or edit them.

```sh
SOURCE_ARCHIVE="$PUBLICATION/<claim path for role source-archive>"
COMPONENT_RELEASE_ARCHIVE="$PUBLICATION/<claim path for role component-release-archive>"
INSTALL_ARCHIVE="$PUBLICATION/<claim path for role install-archive>"

EXPECTED_SOURCE_ARCHIVE_SHA256='<claim digest for source-archive>'
EXPECTED_COMPONENT_RELEASE_ARCHIVE_SHA256='<claim digest for component-release-archive>'
EXPECTED_INSTALL_ARCHIVE_SHA256='<claim digest for install-archive>'
EXPECTED_KERNEL_SHA256='<claim digest for native-executable and selected target>'
```

The verified claim contains exactly one entry for each of those identities.
The selected native attestation has already been checked to name `TARGET`, bind
`EXPECTED_KERNEL_SHA256` and its exact size, and report exact reproduction.

## 4. Verify and safely extract the archives

Verify all three archives and compare each result with its expected claim
digest. Recovery does not compile or use the source archive.

```sh
SOURCE_VERIFY="$(python3 "$ARCHIVE_TOOL" verify "$SOURCE_ARCHIVE")"
COMPONENT_RELEASE_VERIFY="$(
  python3 "$ARCHIVE_TOOL" verify "$COMPONENT_RELEASE_ARCHIVE"
)"
INSTALL_VERIFY="$(python3 "$ARCHIVE_TOOL" verify "$INSTALL_ARCHIVE")"

test "$(printf '%s\n' "$SOURCE_VERIFY" | awk '{print $2}')" = \
  "$EXPECTED_SOURCE_ARCHIVE_SHA256"
test "$(printf '%s\n' "$COMPONENT_RELEASE_VERIFY" | awk '{print $2}')" = \
  "$EXPECTED_COMPONENT_RELEASE_ARCHIVE_SHA256"
test "$(printf '%s\n' "$INSTALL_VERIFY" | awk '{print $2}')" = \
  "$EXPECTED_INSTALL_ARCHIVE_SHA256"

printf '%s\n' "$SOURCE_VERIFY"
printf '%s\n' "$COMPONENT_RELEASE_VERIFY"
printf '%s\n' "$INSTALL_VERIFY"
```

The verifier checks canonical USTAR metadata, manifest-first ordering, the
complete entry set, normalized modes, sizes and SHA-256 digests, and rejects
links, traversal, duplicates, extras, omissions and truncation.

Extract only into absent or empty operator-owned directories:

```sh
COMPONENT_RELEASE_ROOT='<absent-path>/component-release'
INSTALL_ROOT='<absent-path>/install'

test ! -e "$COMPONENT_RELEASE_ROOT"
test ! -e "$INSTALL_ROOT"
python3 "$ARCHIVE_TOOL" extract \
  --out "$COMPONENT_RELEASE_ROOT" \
  "$COMPONENT_RELEASE_ARCHIVE"
python3 "$ARCHIVE_TOOL" extract \
  --out "$INSTALL_ROOT" \
  "$INSTALL_ARCHIVE"
```

Do not modify, copy over, or `chmod` the extracted install tree. The recovery
driver compares that whole tree with the verified install-archive manifest.

## 5. Bind the selected install inputs

Fill these paths from the verified install manifest. The kernel, lifecycle
runner, incumbent, and successor passed to the driver must all be inside
`INSTALL_ROOT`; the executables must be regular executable files and the
packages must be digest-named directories.

```sh
KERNEL="$INSTALL_ROOT/<selected-$TARGET-path>/wasm-biotic-kernel"
LIFECYCLE_RUNNER="$INSTALL_ROOT/<selected-$TARGET-path>/public-key-lifecycle"
PUBLIC_INSTALL_TOOL="$INSTALL_ROOT/<path>/r4-public-install.py"
OPERATOR_CAPACITY="$INSTALL_ROOT/<INSTALL.json operator_capacity path>"
INCUMBENT="$INSTALL_ROOT/<path>/sha256-<incumbent-manifest-hex>"
SUCCESSOR="$INSTALL_ROOT/<path>/sha256-<successor-manifest-hex>"

INCUMBENT_DIGEST="$(python3 -c \
  'import hashlib,pathlib,sys; print("sha256:"+hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' \
  "$INCUMBENT/manifest.json")"
SUCCESSOR_DIGEST="$(python3 -c \
  'import hashlib,pathlib,sys; print("sha256:"+hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' \
  "$SUCCESSOR/manifest.json")"

test "$(basename "$INCUMBENT")" = "sha256-${INCUMBENT_DIGEST#sha256:}"
test "$(basename "$SUCCESSOR")" = "sha256-${SUCCESSOR_DIGEST#sha256:}"
test "$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["previous_graph"])' \
  "$SUCCESSOR/manifest.json")" = "$INCUMBENT_DIGEST"
```

The driver streams and compares the selected kernel bytes with
`EXPECTED_KERNEL_SHA256`. Production `admit` then verifies each package's
certification, manifest-addressed directory, and exact signed artifact closure
against the independently pinned leaf key.

`OPERATOR_CAPACITY` must be the exact canonical file named by the closed
`INSTALL.json.operator_capacity` field. It contains generic mechanism bounds,
exact network ceilings and opaque credential handles, never credential bytes.
The postpublication driver resolves this path automatically, keeps it inside
the verified install tree, and passes the same bytes to every fresh kernel
initialization and to `public-key-lifecycle`. Both retained lifecycle reports
bind its SHA-256 digest.

## 6. Run the public-only recovery gate

The extraction root, work root and both report paths must not exist. They stay
outside the verified publication. The postpublication driver first verifies
the final signed root and independent trust pins; only then does it extract and
run the installed public lifecycle tool from fresh state.

```sh
POST_INSTALL_ROOT='<absent-operator-path>/r4-postpublication-install'
WORK_ROOT='<absent-operator-path>/r4-public-recovery-work'
LIFECYCLE_REPORT='<new-operator-path>/r4-postpublication-lifecycle.json'
RECOVERY_REPORT='<new-operator-path>/r4-postpublication-recovery.json'
WITNESS_ID='<non-secret-operator-witness-id>'
RELEASE_EPOCH='<published-non-negative-unix-epoch>'

test ! -e "$POST_INSTALL_ROOT"
test ! -e "$WORK_ROOT"
test ! -e "$LIFECYCLE_REPORT"
test ! -e "$RECOVERY_REPORT"

python3 "$POST_RECOVERY_TOOL" \
  --publication "$PUBLICATION" \
  --policy "$PINNED_POLICY" \
  --release-public-key "$LEAF_PUBLIC_KEY_RAW" \
  --target "$TARGET" \
  --witness-id "$WITNESS_ID" \
  --extracted-root "$POST_INSTALL_ROOT" \
  --work-root "$WORK_ROOT" \
  --lifecycle-out "$LIFECYCLE_REPORT" \
  --out "$RECOVERY_REPORT" \
  --epoch "$RELEASE_EPOCH"
```

The command executes this exact policy boundary:

1. `wasm-biotic-kernel init` creates fresh state pinned to the incumbent
   manifest, raw leaf public key and installed operator-capacity document.
2. `admit` verifies the incumbent; `serve` bootstraps it.
3. `admit` verifies and instantiates the successor without selecting it.
   Serving that unselected successor must fail, while the incumbent still
   serves.
4. Separate fresh states prove rejection of the wrong leaf key and of a copied
   package with one changed `factory-root.wasm` byte.
5. `public-key-lifecycle` consumes the same operator-capacity bytes, creates its
   own fresh state, bootstraps and runs one useful incumbent component cycle,
   then admits the successor without moving the active pointer.
6. The incumbent Wasm components issue migration and activation; the reloaded
   successor runs one useful component cycle.
7. The driver presents an explicit unhealthy observation. Wasm component
   policy interprets it and requests rollback; native code does not choose
   rollback or interpret health.
8. The runner drops and reopens the process, proves the exact incumbent
   graph/state pair survived, executes the post-rollback component cycle, and
   verifies exact replay without changing mechanism state.

There is intentionally no native `activate` command. Do not invent one. The
kernel CLI accepts `init`, `admit`, and `serve`; upgrade and rollback receipts
must come from admitted Wasm components.

## 7. Verify and retain the reports

The component-owned lifecycle detail remains
`$WORK_ROOT/component-lifecycle.json`. Validate it, `LIFECYCLE_REPORT`, and
`RECOVERY_REPORT` as canonical JSON. At minimum require:

- postpublication recovery `schema` is
  `wasm-biotic.r4-postpublication-recovery.v1`, its phase is
  `post-publication`, and it binds the verified final root, independent policy,
  and exact lifecycle-report digest;
- public lifecycle `schema` is
  `wasm-biotic.r4-public-install-lifecycle.v1` and `outcome` is `pass`;
- expected and observed kernel digests are equal;
- the outer, inner and postpublication wrapper operator-capacity digests are
  equal and name the installed canonical bytes;
- inactive admission kept the incumbent bootable and rejected the unselected
  successor;
- wrong key, tampered package, and automatic successor activation were all
  rejected;
- `private_key_argument_supported` and `private_key_required_or_read` are
  false;
- lifecycle `schema` is
  `wasm-biotic.public-key-only-component-lifecycle.v1` and `outcome` is
  `pass`;
- lifecycle build, signing, and private-key fields are false;
- successor activation and rollback are component-decided;
- restart preserved the rollback pair, all three cycles prove exact replay,
  and the final active manifest equals `INCUMBENT_DIGEST`; and
- the lifecycle-report digest in the public recovery report matches the exact
  lifecycle report bytes.

Retain the independently pinned policy and raw leaf key, the publication root
and verification result, all three archive verification results,
`RECOVERY_REPORT`, `LIFECYCLE_REPORT`, the component lifecycle report, and the
fresh state journal. Any failed or missing fact keeps R4-C6/R4-C7 open;
quarantine the failed roots and restart only with absent roots and new report
paths.

## 8. Trust caveats

R4 is an explicit operator-approved out-of-band genesis/re-root. The R3 leaf
private key was destroyed before it signed any transition, and R3 had no R4
governance policy. Do not describe R4 as an R3-signed rotation or manufacture
cryptographic continuity. Historical R3 packages remain verifiable only under
the retained R3 public key.

R4 proves the canonical 2-of-3 policy and its cryptographic behavior. It does
not prove genuinely separate human custodians, external key locations, or an
independently distributed live policy head. Those custody and current-head
claims belong to R5.

No recovery command above accepts a private key. Do not run the governance
`sign` command, the component package builder, Cargo, a compiler, or any
release-signing workflow during recovery.
