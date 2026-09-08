# Verification snapshot — 2026-09-08

Implementation: `tron-nile-testnet/nile-testnet@c164973fffa4a7fa95ecfa9c0fe793f6761aeb78`.
Only the conformance example is added; the tested production source trees are unchanged.
System and downloaded dependency versions are listed in the parent README and
`SOURCE_LOCK.json`.

## Executed checks

| Check | Result | Scope |
| --- | --- | --- |
| Cold `make test` | PASS | Fresh directory with no conformance dependency/build cache or `node_modules`; a fresh npm cache was used too. This does not imply a fresh OS/system tool installation. |
| Regenerate fixtures | PASS | All eight JSON/binary artifacts match the checked-in bytes. Verification itself does not rewrite the golden vectors. |
| ML-DSA-44 interoperability | PASS | OpenSSL 3.6.3 ↔ BouncyCastle 1.84; identical fixed-seed public key and test-only deterministic signature; bidirectional verification. |
| Falcon interoperability | PASS | Official 2021-11-01 reference ↔ BouncyCastle 1.84; fixed-seed key bytes match on the tested platform; signatures verify in both directions, including imported private test key bodies. |
| Falcon reference self-tests | PASS | External API and the reference distribution's NIST KAT self-tests. |
| Serialization | PASS | `protobufjs`, manual wire encoder, and generated Java agree on reference bytes; semantic decode and reordered-field checks pass. |
| Offline crypto cases | PASS | 19 case rows through the BouncyCastle adapter; the 11 Falcon rows also run through the C reference import adapter. Tagged-key import acceptance is explicitly distinguished from wire rejection. |
| Actual checkout protocol probe | PASS | 41 check groups: 19 crypto/admission rows, 14 single-precompile rows, 6 activation-gate checks, and 2 actual Protobuf-type checks. Valid rows also check the checkout's TRON address derivation. |
| Nile probe safety tests | PASS | 3 tests covering inactive-vs-invalid results, transport/runtime/malformed response failures, and restricted probe addresses/lengths. |
| Negative-command classification | PASS | Missing commands and exit-1-without-explicit-rejection do not satisfy negative assertions. |
| Java source formatting | PASS | Google Java Format 1.24.0. |
| Script syntax and staged whitespace | PASS | Bash / Node syntax checks and `git diff --check`. |

The local protocol probe calls real checkout classes, not replacement implementations.
Malformed argument sizes may produce the primitive's documented `IllegalArgumentException`
instead of a `false` return. Only the expected size rejection is accepted; unrelated
exceptions fail the test. Precompile execution and admission-length results are reported
separately from cryptographic verification.

## Golden fixture fingerprints

| JSON file | SHA-256 |
| --- | --- |
| `fn-dsa-512.json` | `a3be1a81e7d794c0210aa0aed71b1938ab2ed5daf95fc0beaed9e82193744abd` |
| `ml-dsa-44.json` | `74a5ffaf6cba1ec1caf2abd3c960133b972e88508fa6059212cb89291db97809` |

The JSON files describe the test-only seeds, message/public-key/signature hashes, and
binary encodings. Node/chain results are deliberately not encoded as fixture expectations.

## Live Nile observation

See [machine-readable evidence](nile-2026-09-08.json).

- Endpoint: `https://nile.trongrid.io`; Nile genesis ID checked before calls.
- Observed 2026-09-08, approximately **09:32:21–09:32:44 UTC**.
- Node version: **4.8.2.1.PQ1_build1**, unchanged across the run.
- Bracketing head blocks: **70,779,677–70,779,685**, with IDs in the JSON.
- **FN-DSA active (`1`):** valid signature returns 32-byte `1`; eight negative
  inputs return 32-byte `0`. All nine observed results match their expectations.
- **ML-DSA inactive (`0`, omitted JSON scalar):** STATICCALL succeeds with **zero
  return bytes**. This only verifies inactive dispatch. Active ML-DSA verification
  and its four negative precompile calls are **NOT_RUN** on Nile.
- **Zero broadcasts.** No key, funded account, persistent deployment, or state change.
  The start-snapshot witness address is merely the unsigned simulation caller.

This is read-only **execution against live chain state**, not a mined transaction,
historical-block replay, or proof of consensus acceptance. The node's reported version
is not evidence that its binary exactly matches the pinned source commit. Calls use the
moving head; snapshots bracket them rather than claiming one exact execution block.
Reported energy includes the init-code wrapper and is not a charged fee or isolated
precompile benchmark.

## Not executed / deferred

- Active ML-DSA verification on Nile: **NOT_RUN — activation flag is 0**.
- Future missing-`key_ref` path: **DEFERRED — specification and implementation pending**.
- Full PQ transaction permission/weight checks, SR blocks, P2P, batch/multisig precompiles,
  wallet derivation/recovery, and consensus replay: **OUT_OF_SCOPE / NOT_RUN**.
- Linux, other architectures, and CI integration: **NOT_RUN / NOT_INCLUDED**.
- Full repository test suite and Sonar scan: **NOT_RUN**; this addition has focused
  executable conformance checks rather than a full-node regression claim.

The checked-in result is a dated snapshot. New local results go to ignored
`build/reports/`; update published evidence explicitly after reviewing a new run.
