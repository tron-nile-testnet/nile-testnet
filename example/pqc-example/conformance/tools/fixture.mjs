#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import protobuf from "protobufjs";
import sha3 from "js-sha3";
import { caseManifest } from "./cases.mjs";

const { keccak256 } = sha3;
const HERE = path.dirname(fileURLToPath(import.meta.url));
const PROTO_PATH = path.join(HERE, "..", "proto", "pq_auth_sig.proto");
const IMPLEMENTATION_COMMIT = "c164973fffa4a7fa95ecfa9c0fe793f6761aeb78";

const SCHEMES = Object.freeze({
  FN_DSA_512: {
    id: 1,
    publicKeyLength: 896,
    signatureMinLength: 617,
    signatureMaxLength: 667,
    signatureHeader: 0x39,
    precompileAddress: "0x02000016",
    precompileInputLength: 1594,
    signatureEncoding: "0x39 || salt || s2_compressed",
    publicKeyEncoding: "Falcon-512 h polynomial without the 0x09 reference header",
  },
  ML_DSA_44: {
    id: 2,
    publicKeyLength: 1312,
    signatureMinLength: 2420,
    signatureMaxLength: 2420,
    precompileAddress: "0x02000018",
    precompileInputLength: 3764,
    signatureEncoding: "FIPS 204 ML-DSA-44 signature",
    publicKeyEncoding: "FIPS 204 rho || t1",
  },
});

const root = await protobuf.load(PROTO_PATH);
const PQAuthSig = root.lookupType("protocol.PQAuthSig");
const TransactionPQAuthSigField = root.lookupType("protocol.TransactionPQAuthSigField");

function usage() {
  console.error("Usage:");
  console.error(
    "  fixture.mjs generate <scheme> <message.bin> <public-key.bin> <signature.bin> " +
      "<fixture.json> <producer> [key-seed-hex] [signing-entropy-hex]",
  );
  console.error("  fixture.mjs check <fixture.json> [fixture.json ...]");
  process.exit(2);
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest();
}

function sha256Hex(bytes) {
  return sha256(bytes).toString("hex");
}

function tronAddress(publicKey) {
  const digest = Buffer.from(keccak256(publicKey), "hex");
  return Buffer.concat([Buffer.from([0x41]), digest.subarray(12)]);
}

function base58(bytes) {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let value = BigInt(`0x${bytes.toString("hex") || "0"}`);
  let encoded = "";
  while (value > 0n) {
    const remainder = Number(value % 58n);
    value /= 58n;
    encoded = alphabet[remainder] + encoded;
  }
  let leadingZeros = 0;
  while (leadingZeros < bytes.length && bytes[leadingZeros] === 0) {
    leadingZeros += 1;
  }
  return "1".repeat(leadingZeros) + (encoded || "1");
}

function base58Check(address) {
  const checksum = sha256(sha256(address)).subarray(0, 4);
  return base58(Buffer.concat([address, checksum]));
}

function encodeVarint(value) {
  assert(Number.isSafeInteger(value) && value >= 0, "varint input must be non-negative");
  const output = [];
  do {
    let next = value & 0x7f;
    value = Math.floor(value / 128);
    if (value !== 0) next |= 0x80;
    output.push(next);
  } while (value !== 0);
  return Buffer.from(output);
}

function encodeBytesField(fieldNumber, value) {
  return Buffer.concat([
    encodeVarint((fieldNumber << 3) | 2),
    encodeVarint(value.length),
    value,
  ]);
}

function encodePQAuthSigManually(schemeId, publicKey, signature) {
  return Buffer.concat([
    encodeVarint((1 << 3) | 0),
    encodeVarint(schemeId),
    encodeBytesField(2, publicKey),
    encodeBytesField(3, signature),
  ]);
}

function buildPrecompileInput(schemeName, message, publicKey, signature) {
  if (schemeName === "ML_DSA_44") {
    return Buffer.concat([message, signature, publicKey]);
  }
  const signatureBody = signature.subarray(1);
  const signatureSlot = Buffer.alloc(666);
  signatureBody.copy(signatureSlot);
  return Buffer.concat([message, signatureSlot, publicKey]);
}

function validateRaw(schemeName, message, publicKey, signature) {
  const scheme = SCHEMES[schemeName];
  assert(scheme, `unsupported scheme: ${schemeName}`);
  assert.equal(message.length, 32, "TIP-899 precompile fixture message must be 32 bytes");
  assert.equal(
    publicKey.length,
    scheme.publicKeyLength,
    `${schemeName} public key length mismatch`,
  );
  assert(
    signature.length >= scheme.signatureMinLength &&
      signature.length <= scheme.signatureMaxLength,
    `${schemeName} signature length mismatch: ${signature.length}`,
  );
  if (scheme.signatureHeader !== undefined) {
    assert.equal(signature[0], scheme.signatureHeader, "non-canonical Falcon signature header");
  }
}

function artifactNames(fixturePath) {
  const parsed = path.parse(fixturePath);
  const prefix = path.join(parsed.dir, parsed.name);
  return {
    pqAuthSig: `${prefix}.pq-auth-sig.bin`,
    transactionField: `${prefix}.transaction-field.bin`,
    precompileInput: `${prefix}.precompile-input.bin`,
  };
}

async function generate(args) {
  if (args.length < 6 || args.length > 8) usage();
  const [
    schemeName,
    messagePath,
    publicKeyPath,
    signaturePath,
    fixturePath,
    producer,
    keySeedHex,
    signingEntropyHex,
  ] = args;
  const scheme = SCHEMES[schemeName];
  if (!scheme) usage();
  const message = fs.readFileSync(messagePath);
  const publicKey = fs.readFileSync(publicKeyPath);
  const signature = fs.readFileSync(signaturePath);
  validateRaw(schemeName, message, publicKey, signature);

  const protobufValue = { scheme: scheme.id, publicKey, signature };
  const verificationError = PQAuthSig.verify(protobufValue);
  assert.equal(verificationError, null, verificationError ?? "valid protobuf value");
  const pqAuthSig = Buffer.from(PQAuthSig.encode(PQAuthSig.create(protobufValue)).finish());
  const manual = encodePQAuthSigManually(scheme.id, publicKey, signature);
  assert.deepEqual(pqAuthSig, manual, "protobufjs and manual wire encoders disagree");

  const transactionField = Buffer.from(
    TransactionPQAuthSigField.encode(
      TransactionPQAuthSigField.create({ pqAuthSig: [protobufValue] }),
    ).finish(),
  );
  assert.deepEqual(
    transactionField,
    encodeBytesField(6, pqAuthSig),
    "Transaction.pq_auth_sig field encoding mismatch",
  );

  const precompileInput = buildPrecompileInput(
    schemeName,
    message,
    publicKey,
    signature,
  );
  assert.equal(precompileInput.length, scheme.precompileInputLength);
  const address = tronAddress(publicKey);
  const names = artifactNames(fixturePath);
  const relative = (file) => path.relative(path.dirname(fixturePath), file);

  const fixture = {
    schemaVersion: 2,
    vectorId: `${schemeName.toLowerCase().replaceAll("_", "-")}-incrementing-seed`,
    source: {
      tip: "https://github.com/tronprotocol/tips/issues/899",
      implementationRepository: "https://github.com/tron-nile-testnet/nile-testnet",
      implementationCommit: IMPLEMENTATION_COMMIT,
    },
    provenance: {
      producer,
      keySeedHex: keySeedHex ?? null,
      signingEntropyHex: signingEntropyHex ?? null,
      testOnly: true,
      warning: "Public fixed seeds and signing entropy: NEVER use for real keys or transactions.",
    },
    scheme: {
      name: schemeName,
      protobufValue: scheme.id,
    },
    message: {
      role: "Synthetic 32-byte verification message; not the ID of a real transaction",
      length: message.length,
      hex: message.toString("hex"),
      sha256: sha256Hex(message),
    },
    publicKey: {
      encoding: scheme.publicKeyEncoding,
      length: publicKey.length,
      hex: publicKey.toString("hex"),
      sha256: sha256Hex(publicKey),
    },
    signature: {
      encoding: scheme.signatureEncoding,
      length: signature.length,
      hex: signature.toString("hex"),
      sha256: sha256Hex(signature),
    },
    tronAddress: {
      derivation: "0x41 || Keccak-256(public_key)[12..32]",
      hex: address.toString("hex"),
      base58Check: base58Check(address),
    },
    protobuf: {
      pqAuthSigLength: pqAuthSig.length,
      pqAuthSigHex: pqAuthSig.toString("hex"),
      pqAuthSigFile: relative(names.pqAuthSig),
      semanticsNormative: true,
      encodingRole: "One deterministic reference encoding; not universal Protobuf canonicalization",
      transactionRole: "Field-6-only fragment, NOT a complete or broadcastable transaction",
      transactionFieldNumber: 6,
      transactionFieldLength: transactionField.length,
      transactionFieldHex: transactionField.toString("hex"),
      transactionFieldFile: relative(names.transactionField),
    },
    precompile: {
      address: scheme.precompileAddress,
      inputLayout:
        schemeName === "ML_DSA_44"
          ? "message[32] || signature[2420] || public_key[1312]"
          : "message[32] || signature_without_0x39[<=666], right-zero-padded to 666 || public_key[896]",
      inputLength: precompileInput.length,
      inputHex: precompileInput.toString("hex"),
      inputFile: relative(names.precompileInput),
      expectedOutputHex: `${"00".repeat(31)}01`,
      expectedCondition: "Scheme active; exact input processed by the single-verify precompile",
      observedResults: "Recorded separately in reports; this field is not a chain observation",
    },
    negativeCases: caseManifest(schemeName),
  };

  if (schemeName === "FN_DSA_512") {
    fixture.referenceRepresentation = {
      publicKeyHex: "09" + publicKey.toString("hex"),
      publicKeyLength: 897,
      importRule: "Require 0x09 then strip it; the 897-byte reference key is invalid on the TRON wire",
      signatureRule: "Keep 0x39 in PQAuthSig; remove it only for the 666-byte zero-padded TVM slot",
    };
  }
  fs.mkdirSync(path.dirname(fixturePath), { recursive: true });
  fs.writeFileSync(names.pqAuthSig, pqAuthSig);
  fs.writeFileSync(names.transactionField, transactionField);
  fs.writeFileSync(names.precompileInput, precompileInput);
  fs.writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`);
  await checkFixture(fixturePath);
  console.log(
    `generated=${fixturePath} scheme=${schemeName} protobufBytes=${pqAuthSig.length} ` +
      `precompileBytes=${precompileInput.length}`,
  );
}

async function checkFixture(fixturePath) {
  const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  assert.equal(fixture.schemaVersion, 2);
  assert.equal(fixture.source.implementationCommit, IMPLEMENTATION_COMMIT);
  const schemeName = fixture.scheme.name;
  const scheme = SCHEMES[schemeName];
  assert(scheme, `unknown fixture scheme: ${schemeName}`);
  assert.equal(fixture.scheme.protobufValue, scheme.id);
  assert.equal(fixture.provenance.testOnly, true);
  assert.deepEqual(fixture.negativeCases, caseManifest(schemeName));
  assert.equal(fixture.precompile.expectedOutputHex, "00".repeat(31) + "01");

  const message = Buffer.from(fixture.message.hex, "hex");
  const publicKey = Buffer.from(fixture.publicKey.hex, "hex");
  const signature = Buffer.from(fixture.signature.hex, "hex");
  validateRaw(schemeName, message, publicKey, signature);
  assert.equal(fixture.message.length, message.length);
  assert.equal(fixture.publicKey.length, publicKey.length);
  assert.equal(fixture.signature.length, signature.length);
  if (schemeName === "FN_DSA_512") {
    assert.equal(fixture.referenceRepresentation.publicKeyHex, "09" + publicKey.toString("hex"));
    assert.equal(fixture.referenceRepresentation.publicKeyLength, 897);
  }
  assert.equal(fixture.message.sha256, sha256Hex(message));
  assert.equal(fixture.publicKey.sha256, sha256Hex(publicKey));
  assert.equal(fixture.signature.sha256, sha256Hex(signature));
  const address = tronAddress(publicKey);
  assert.equal(fixture.tronAddress.hex, address.toString("hex"));
  assert.equal(fixture.tronAddress.base58Check, base58Check(address));

  const decoded = PQAuthSig.decode(Buffer.from(fixture.protobuf.pqAuthSigHex, "hex"));
  assert.equal(decoded.scheme, scheme.id);
  assert.deepEqual(Buffer.from(decoded.publicKey), publicKey);
  assert.deepEqual(Buffer.from(decoded.signature), signature);
  // A legal alternative field order must decode to the same semantics.
  const reordered = Buffer.concat([
    encodeBytesField(3, signature), encodeBytesField(2, publicKey),
    encodeVarint(8), encodeVarint(scheme.id),
  ]);
  const alternative = PQAuthSig.decode(reordered);
  assert.equal(alternative.scheme, scheme.id);
  assert.deepEqual(Buffer.from(alternative.publicKey), publicKey);
  assert.deepEqual(Buffer.from(alternative.signature), signature);
  assert.deepEqual(encodePQAuthSigManually(scheme.id, publicKey, signature),
    Buffer.from(fixture.protobuf.pqAuthSigHex, "hex"));
  const reencoded = Buffer.from(PQAuthSig.encode(decoded).finish());
  assert.equal(reencoded.toString("hex"), fixture.protobuf.pqAuthSigHex);
  assert.equal(reencoded.length, fixture.protobuf.pqAuthSigLength);

  const transactionField = Buffer.from(fixture.protobuf.transactionFieldHex, "hex");
  const decodedTransaction = TransactionPQAuthSigField.decode(transactionField);
  assert.equal(decodedTransaction.pqAuthSig.length, 1);
  assert.equal(decodedTransaction.pqAuthSig[0].scheme, scheme.id);
  assert.deepEqual(Buffer.from(decodedTransaction.pqAuthSig[0].publicKey), publicKey);
  assert.deepEqual(Buffer.from(decodedTransaction.pqAuthSig[0].signature), signature);

  const precompileInput = buildPrecompileInput(schemeName, message, publicKey, signature);
  assert.equal(precompileInput.toString("hex"), fixture.precompile.inputHex);
  assert.equal(precompileInput.length, fixture.precompile.inputLength);
  assert.equal(precompileInput.length, scheme.precompileInputLength);

  const baseDir = path.dirname(fixturePath);
  const binaryChecks = [
    [fixture.protobuf.pqAuthSigFile, reencoded],
    [fixture.protobuf.transactionFieldFile, transactionField],
    [fixture.precompile.inputFile, precompileInput],
  ];
  for (const [relativePath, expected] of binaryChecks) {
    assert.deepEqual(fs.readFileSync(path.join(baseDir, relativePath)), expected);
  }
  console.log(`checked=${fixturePath} scheme=${schemeName} valid=true`);
}

const [, , command, ...args] = process.argv;
if (command === "generate") {
  await generate(args);
} else if (command === "check" && args.length > 0) {
  for (const fixturePath of args) {
    await checkFixture(fixturePath);
  }
} else {
  usage();
}
