# TIP-899 conformance fixtures

A small, independent fixture baseline for wallets, SDKs, and developer tools.
It covers **FN-DSA-512 (Falcon-512)** and **ML-DSA-44**, their TRON address and
Protobuf encodings, and the two single-verify TVM precompiles. No production
code, consensus rule, transaction format, or dependency of the node is changed.

Reference implementation: [`c164973fffa4a7fa95ecfa9c0fe793f6761aeb78`](https://github.com/tron-nile-testnet/nile-testnet/commit/c164973fffa4a7fa95ecfa9c0fe793f6761aeb78)
on `release_post_quantum`. See the [requested scope](https://github.com/tronprotocol/tips/issues/899#issuecomment-5578559268)
and [source/dependency lock](SOURCE_LOCK.json).

> **TEST ONLY:** The fixed seeds and deterministic signing entropy in these
> fixtures are public. Never use them for a real account, wallet backup, witness,
> or transaction. Generated private test keys stay in ignored `build/`; they are
> not part of the published fixtures. These seeds do not define a wallet derivation
> or recovery standard. Falcon seed reproduction here is platform-specific, not
> a cross-platform seed-portability guarantee.

## Prerequisites and exact commands

The validated reproduction platform is **macOS 26.5.2 (25F84), arm64**.
Other platforms have **not been tested**. The bootstrap intentionally rejects
other OS/architecture combinations rather than downloading an incompatible `protoc`.
There is no Linux or CI claim in this contribution.

| Tool | Tested version / source |
| --- | --- |
| OpenSSL | 3.6.3, including ML-DSA-44 and deterministic signing support |
| JDK (`java`, `javac`) | Temurin 17.0.19+10 |
| Node.js / npm | 20.19.2 / 10.8.2 |
| Python | 3.12.1, standard library only |
| C compiler | Apple clang 21.0.0 (`clang-2100.1.1.101`) |
| Falcon reference | Official 2021-11-01 C archive, SHA-256 locked |
| BouncyCastle | `bcprov-jdk18on` 1.84, SHA-256 locked |
| Protobuf | `protoc` / `protobuf-java` 3.25.8, SHA-256 locked; compiler prints `libprotoc 25.8` |
| JavaScript libraries | `protobufjs` 8.8.0, `js-sha3` 0.13.0, transitive versions/integrities in `package-lock.json` |

Also put `bash`, `make`, `curl`, `unzip`, and `shasum` on `PATH`.
Supply these system tools yourself; bootstrap does not install global software.
Set `OPENSSL` to an absolute executable path if the desired OpenSSL is not first
on `PATH`. Downloads use public HTTPS sources and checked hashes; npm uses `npm ci`
with lifecycle scripts disabled. Initial setup needs network access. Dependencies
and generated code stay inside this directory's ignored `.cache/` and `build/`.

From a checkout containing this contribution:

```bash
cd example/pqc-example/conformance
make verify       # read checked-in fixtures; never regenerate/overwrite them
make reproduce    # generate into build/regenerated-fixtures and compare every file
# Or run both, in order:
make test

# Additional validation through the actual checkout (builds framework classes):
make protocol

# Optional live Nile check, read-only, no key or funded account required:
make nile
```

`make prepare` explicitly regenerates the checked-in fixtures. It is for intentional
fixture maintenance, not verification. Scripts return nonzero on unexpected results;
missing executables, I/O errors, crashes, and malformed responses do **not** count as
successful negative tests.

For a cold reproduction, use a fresh copy without `.cache/`, `build/`, or
`node_modules/` and run the commands above. The recorded cold run covers `make test`;
`make protocol` additionally uses the upstream Gradle build and its dependencies.

## What the fixtures mean

Each JSON file contains a synthetic 32-byte message, algorithm identifier, canonical
public key, headed transaction signature, derived 21-byte TRON address (hex and
Base58Check), deterministic reference Protobuf bytes, precompile input, and explicit
negative-case definitions. Companion `.bin` files are the same bytes for consumers
that do not parse JSON hex. No fixture is a signed or broadcastable transaction.

**Protobuf field semantics are normative; a universal canonical serialization is
not claimed.** The local proto is a minimal, wire-compatible projection of
`protocol/src/main/protos/core/Tron.proto` at the pinned commit. Its generated Java
namespace deliberately differs from the node's full generated `Protocol` class.

The reference encoders emit known fields in field-number order. Verification checks
semantic fields through `protobufjs`, generated Java, and a small manual wire encoder;
a reordered `PQAuthSig` must decode to the same values. The transaction artifact
contains **only repeated field 6**: it has no `raw_data`, account permission checks,
or transaction ID of its own. `make protocol` also decodes and re-encodes the bytes
with the checkout's actual `Protocol.PQAuthSig` and `Protocol.Transaction` classes.

### Falcon representation boundaries

- The wire/address public key is **896-byte `h`**; address derivation is
  `0x41 || Keccak-256(h)[12..32]`.
- A reference import is **897-byte `0x09 || h`**. Check `0x09` before stripping it.
  The fixture explicitly includes both public representations.
- `PQAuthSig.signature` keeps **`0x39 || salt || s2_compressed`** (617–667 bytes).
- The TVM signature slot removes `0x39` and right-zero-pads the body to **666 bytes**.
  The single-verify input is `message[32] || slot[666] || h[896]` (1,594 bytes).
- Reference private-key imports use `0x59 || f || g || F`; the raw private body is
  1,280 bytes. Private-key representations are not consensus fields or published fixtures.

The C helper intentionally accepts the reference public-key header as an **import
adapter**. That import verifies cryptographically, while the same 897-byte key is
rejected by the TRON wire validator. These are separate checks, not conflicting results.

ML-DSA-44 uses a 1,312-byte standard public key and a 2,420-byte signature. Its input
is `message[32] || signature[2420] || public_key[1312]` (3,764 bytes).

## Verification layers and negative cases

| Layer | Execution / evidence |
| --- | --- |
| Independent crypto | OpenSSL ↔ BouncyCastle for ML-DSA-44; official Falcon reference ↔ BouncyCastle for FN-DSA-512. Fixed-seed keys and selected deterministic outputs are compared; signatures verify in both directions. Falcon's external API and NIST KAT self-tests run too. |
| Serialization | Semantic field checks, deterministic byte comparisons, TRON address derivation, and fixed-slot construction. This alone is not precompile execution. |
| Local protocol | `make protocol` calls the checkout's real `PQAuthSigValidator`, `PQSchemeRegistry`, precompile dispatcher, and single-verify implementations. No mocked validator or chain DB is used. |
| Live chain state | `make nile` invokes read-only TVM simulation against a public Nile node. This is **not a mined transaction or consensus replay**. |

`tools/cases.mjs` defines reproducible mutations, also listed in each fixture:
message/signature mutation; short/long public keys; Falcon's tagged public key and
wrong signature header; and synthetic signatures at lengths 616/617/667/668
(Falcon) or 2419/2420/2421 (ML-DSA). **An in-range synthetic signature can pass the
length gate and still fail cryptographic verification.**

Precompile cases are separate from wire cases because the Falcon slot has a different
representation. They cover mutation, strict total-input length, an incorrectly retained
header, tagged public key, nonzero padding, and an empty signature slot. Expected
32-byte outputs apply **only when the relevant scheme is active**.

Local protocol checks turn each flag on/off independently. An inactive single-verify
precompile is not registered: a successful TVM call to its empty address can return
**zero bytes**, not a 32-byte zero word. The Nile probe records STATICCALL success,
return-data length, and actual bytes separately to prevent a false pass.

**Future missing-`key_ref` cases: DEFERRED.** No encoding, rejection rule, or passing
result is invented before that flow is specified and implemented.

## Nile method and recorded results

The runner is restricted to `https://nile.trongrid.io` and verifies Nile's genesis
block ID before executing. It uses `wallet/triggerconstantcontract`'s empty-contract-
address creation-simulation path in `Wallet.triggerConstantContract`. Small init code
copies the fixture input, makes a STATICCALL, and returns its status, return-data size,
and bytes. It creates **no persistent contract** and sends **no signed transaction**.
The public witness address from the start-snapshot head block is fixed as the simulation owner;
no key, account funds, signing API, or broadcast API is used.

Calls execute against moving head state. The report brackets the run with block IDs,
node version, and activation flags; it does not claim a single pinned execution block.
API/runtime errors and changed activation flags fail the run instead of counting as
invalid signatures. Energy figures include the simulation wrapper and are **not**
precompile-only benchmarks or fees charged to an account.

The [2026-09-08 observation](reports/nile-2026-09-08.json) records:

- Node `4.8.2.1.PQ1_build1`; bracketing head blocks **70,779,677–70,779,685**.
- `getAllowFnDsa512 = 1`: valid fixture returns 32-byte `1`; all eight negative
  precompile inputs return 32-byte `0`.
- `getAllowMlDsa44 = 0` (the JSON `value` is omitted for zero): only inactive dispatch
  was observed, with an empty return. **ML-DSA active-chain verification is NOT_RUN.**
- No broadcasts; no full transaction authorization, SR block, P2P, batch/multisig,
  wallet recovery, or future Phase 2 claim.

These are dated observations, not permanent assertions about Nile's configuration.
Rerunning `make nile` writes a new report to ignored `build/reports/nile.json`, never
silently overwriting the published observation. If ML-DSA becomes active, the same
runner exercises its positive and negative precompile cases.

## Outputs and scope

- Checked-in expected data: `fixtures/`, with source references and test-only labels.
- Dated observed evidence: `reports/`; values are distinct from fixture expectations.
- Local reproducible output: `build/reports/` (versions, interoperability, crypto cases,
  protocol checks, Nile report); full local Nile request/response evidence is under
  `build/nile-evidence/`.
- `SOURCE_LOCK.json` records sources and dependency hashes; it is not a security
  certification, wallet KDF standard, or claim of full chain-level conformance.

See [verification summary](reports/verification-2026-09-08.md) for executed checks and
explicitly unverified/deferred coverage. No Linux support, CI integration, or consensus
changes are included in this PR.
