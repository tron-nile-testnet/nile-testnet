import test from "node:test";
import assert from "node:assert/strict";
import { parseProbeResult, assessObservation, buildProbe } from "./nile.mjs";
const word = n => n.toString(16).padStart(64, "0");
const response = hex => ({ result: { result: true }, constant_result: [hex] });

test("distinguish an inactive call from an active invalid signature", () => {
  const inactive = parseProbeResult(response(word(1) + word(0)));
  const invalid = parseProbeResult(response(word(1) + word(32) + word(0)));
  assert.equal(assessObservation(inactive, false, word(1)), "PASS_INACTIVE_DISPATCH_ONLY");
  assert.equal(assessObservation(invalid, true, word(0)), "PASS_ACTIVE_PRECOMPILE");
  assert.throws(() => assessObservation(inactive, true, word(0)));
  assert.throws(() => assessObservation(invalid, false, word(0)));
  assert.throws(() => assessObservation(invalid, true, word(1)));
});

test("transport, runtime, and malformed results cannot count as negative passes", () => {
  for (const value of [
    {}, { result: { result: false } },
    response(word(0) + word(0)),
    response(word(1) + word(32)),
    response(word(1) + word(0) + word(0)),
    response("invalid"),
    { ...response(word(1) + word(0)), result: { result: true, message: "REVERT" } },
    { ...response(word(1) + word(0)), transaction: { ret: [{ contractRet: "OUT_OF_ENERGY" }] } },
  ]) assert.throws(() => parseProbeResult(value));
});

test("only the two requested PQ single-verify addresses are accepted", () => {
  assert.throws(() => buildProbe("0x00000001", Buffer.alloc(10)));
  assert.throws(() => buildProbe("0x02000016", Buffer.alloc(65536)));
  const payload = Buffer.from("012345", "hex");
  const code = buildProbe("0x02000016", payload);
  assert.deepEqual(code.subarray(code.readUInt16BE(4)), payload);
});
