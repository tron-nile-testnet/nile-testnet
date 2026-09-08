// Inputs are public test vectors. Expected values describe separate validation layers.
export function cryptoCaseDefinitions(scheme) {
  const falcon = scheme === "FN_DSA_512";
  const sizes = falcon ? [616, 617, 667, 668] : [2419, 2420, 2421];
  return [
    { id: "valid", mutation: { op: "none" }, expectedVerify: true, expectedLengthCheck: true },
    { id: "tampered-message", mutation: { op: "xor", field: "message", offset: 0 }, expectedVerify: false, expectedLengthCheck: true },
    { id: "tampered-signature", mutation: { op: "xor", field: "signature", offset: 1 }, expectedVerify: false, expectedLengthCheck: true },
    { id: "short-public-key", mutation: { op: "truncate", field: "publicKey" }, expectedVerify: false, expectedLengthCheck: false },
    { id: "long-public-key", mutation: { op: "append-zero", field: "publicKey" }, expectedVerify: false, expectedLengthCheck: false },
    ...sizes.map(length => ({
      id: `synthetic-signature-length-${length}`,
      mutation: { op: "synthetic-signature", length },
      expectedVerify: false,
      expectedLengthCheck: falcon ? length >= 617 && length <= 667 : length === 2420,
    })),
    ...(falcon ? [
      { id: "reference-tagged-public-key", mutation: { op: "prepend-09", field: "publicKey" }, expectedVerify: false, expectedLengthCheck: false, expectedReferenceImportVerify: true },
      { id: "wrong-signature-header", mutation: { op: "xor", field: "signature", offset: 0 }, expectedVerify: false, expectedLengthCheck: true },
    ] : []),
  ];
}

export function precompileCaseDefinitions(scheme) {
  return [
    { id: "valid", mutation: "none", expectedWord: 1 },
    { id: "tampered-message", mutation: "xor-message-byte-0", expectedWord: 0 },
    { id: "tampered-signature", mutation: "xor-signature-slot-byte-0", expectedWord: 0 },
    { id: "short-input", mutation: "remove-last-byte", expectedWord: 0 },
    { id: "trailing-byte", mutation: "append-zero-byte", expectedWord: 0 },
    ...(scheme === "FN_DSA_512" ? [
      { id: "reference-tagged-public-key", mutation: "insert-09-before-public-key", expectedWord: 0 },
      { id: "header-retained-in-slot", mutation: "put-headered-signature-in-slot", expectedWord: 0 },
      { id: "nonzero-slot-padding", mutation: "set-last-padding-byte-to-01", expectedWord: 0 },
      { id: "empty-signature-slot", mutation: "zero-signature-slot", expectedWord: 0 },
    ] : []),
  ];
}

export function caseManifest(scheme) {
  return {
    wireAndCrypto: cryptoCaseDefinitions(scheme).filter(c => c.id !== "valid"),
    precompileWhenActive: precompileCaseDefinitions(scheme).filter(c => c.id !== "valid"),
    inactiveScheme: {
      layer: "precompile-dispatch",
      condition: "The scheme's activation flag is 0",
      expected: "Precompile is not registered; do not interpret an empty return as a 32-byte zero",
    },
    missingKeyRef: {
      status: "DEFERRED",
      reason: "Await the specification and implementation of the future key_ref flow",
    },
    results: "Execution results live in reports, not in the expected-value definitions",
  };
}

export function cryptoCases(fixture) {
  return cryptoCaseDefinitions(fixture.scheme.name).map(definition => {
    const data = Object.fromEntries(["message", "publicKey", "signature"].map(
      key => [key, Buffer.from(fixture[key].hex, "hex")],
    ));
    const m = definition.mutation;
    if (m.op === "xor") data[m.field][m.offset] ^= 1;
    else if (m.op === "truncate") data[m.field] = data[m.field].subarray(0, -1);
    else if (m.op === "append-zero") data[m.field] = Buffer.concat([data[m.field], Buffer.from([0])]);
    else if (m.op === "prepend-09") data[m.field] = Buffer.concat([Buffer.from([9]), data[m.field]]);
    else if (m.op === "synthetic-signature") {
      data.signature = Buffer.alloc(m.length);
      if (fixture.scheme.name === "FN_DSA_512") data.signature[0] = 0x39;
    } else if (m.op !== "none") throw new Error(`Unknown mutation: ${m.op}`);
    return { ...definition, ...data };
  });
}

export function precompileCases(fixture) {
  return precompileCaseDefinitions(fixture.scheme.name).map(definition => {
    let input = Buffer.from(fixture.precompile.inputHex, "hex");
    switch (definition.mutation) {
      case "none": break;
      case "xor-message-byte-0": input[0] ^= 1; break;
      case "xor-signature-slot-byte-0": input[32] ^= 1; break;
      case "remove-last-byte": input = input.subarray(0, -1); break;
      case "append-zero-byte": input = Buffer.concat([input, Buffer.from([0])]); break;
      case "insert-09-before-public-key":
        input = Buffer.concat([input.subarray(0, 698), Buffer.from([9]), input.subarray(698)]); break;
      case "put-headered-signature-in-slot": {
        const signature = Buffer.from(fixture.signature.hex, "hex");
        if (signature.length > 666) throw new Error("This mutation requires a <=666-byte fixture signature");
        input.fill(0, 32, 698); signature.copy(input, 32); break;
      }
      case "set-last-padding-byte-to-01":
        if (fixture.signature.length - 1 >= 666) throw new Error("Fixture must have signature padding");
        input[697] = 1; break;
      case "zero-signature-slot": input.fill(0, 32, 698); break;
      default: throw new Error(`Unknown precompile mutation: ${definition.mutation}`);
    }
    return { ...definition, input, expectedOutputHex: "00".repeat(31) + (definition.expectedWord ? "01" : "00") };
  });
}
