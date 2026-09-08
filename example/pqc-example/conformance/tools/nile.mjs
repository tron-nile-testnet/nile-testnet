#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { precompileCases } from "./cases.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENDPOINT = "https://nile.trongrid.io";
const NILE_GENESIS = "0000000000000000d698d4192c56cb6be724a558448e2684802de4d6cd8690dc";
const READ_ONLY_PATHS = new Set([
  "/wallet/getblockbynum", "/wallet/getnowblock", "/wallet/getnodeinfo",
  "/wallet/getchainparameters", "/wallet/triggerconstantcontract",
]);
const sha256 = bytes => crypto.createHash("sha256").update(bytes).digest("hex");

function request(apiPath, body = {}) {
  assert(READ_ONLY_PATHS.has(apiPath), "only approved read-only Nile APIs are available");
  // curl uses the host trust store. Never disable TLS validation, sign, deploy, or broadcast.
  const result = spawnSync("curl", ["-q", "--fail", "--silent", "--show-error",
    "--proto", "=https", "--max-time", "30", "-H", "Content-Type: application/json",
    "--data-binary", "@-", ENDPOINT + apiPath],
  { input: JSON.stringify(body), encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

export function buildProbe(address, input) {
  assert(["0x02000016", "0x02000018"].includes(address), "single-verify PQ addresses only");
  assert(input.length < 65536, "PUSH2 input length overflow");
  const size = input.length.toString(16).padStart(4, "0");
  // Init code for a constant creation simulation (no deployed contract):
  // CODECOPY payload to memory[256..]; STATICCALL precompile with no output copy;
  // return success[32] || RETURNDATASIZE[32] || exact return data.
  // Measuring return size prevents a disabled/empty account call from looking like word zero.
  const code = Buffer.from("61" + size + "61000061010039" +
    "6000600061" + size + "61010063" + address.slice(2) +
    "5afa6000523d80602052600060403e3d6040016000f3", "hex");
  code.writeUInt16BE(code.length, 4);
  return Buffer.concat([code, input]);
}

export function parseProbeResult(response) {
  assert.equal(response.result?.result, true, JSON.stringify(response.result));
  assert(!response.result.message, "constant call reported an execution error");
  for (const result of response.transaction?.ret || []) {
    assert(!result.contractRet || result.contractRet === "SUCCESS", "transaction execution failed");
    assert(!result.ret || result.ret === "SUCESS", "constant transaction result failed");
  }
  assert.equal(response.constant_result?.length, 1, "missing or ambiguous constant result");
  const hex = response.constant_result[0];
  assert(typeof hex === "string" && /^(?:[0-9a-fA-F]{2})+$/.test(hex), "invalid result hex");
  const bytes = Buffer.from(hex, "hex");
  assert(bytes.length >= 64, "truncated probe envelope");
  const callSuccess = BigInt("0x" + bytes.subarray(0, 32).toString("hex"));
  const size = BigInt("0x" + bytes.subarray(32, 64).toString("hex"));
  assert.equal(callSuccess, 1n, "STATICCALL failed; not a negative signature result");
  assert(size <= 32n, "unexpected PQ result length");
  assert.equal(bytes.length, 64 + Number(size), "return length mismatch");
  return { staticCallSuccess: true, returnDataLength: Number(size), outputHex: bytes.subarray(64).toString("hex") };
}

function snapshot() {
  const node = request("/wallet/getnodeinfo");
  const parameters = request("/wallet/getchainparameters");
  const block = request("/wallet/getnowblock");
  const flags = {};
  for (const key of ["getAllowFnDsa512", "getAllowMlDsa44"]) {
    const entry = parameters.chainParameter?.find(p => p.key === key);
    assert(entry, `missing activation parameter ${key}`);
    const value = entry.value ?? 0; // Protobuf JSON omits scalar value=0.
    assert([0, 1].includes(value), `unsupported activation value ${value}`);
    flags[key] = { value, valueOmittedInResponse: entry.value === undefined };
  }
  assert(node.configNodeInfo?.codeVersion, "missing node code version");
  assert(block.blockID && block.block_header?.raw_data?.witness_address, "missing head block");
  return {
    at: new Date().toISOString(),
    nodeVersion: node.configNodeInfo.codeVersion,
    p2pVersion: node.configNodeInfo.p2pVersion,
    nodeReportedHead: node.block,
    head: { number: block.block_header.raw_data.number, id: block.blockID,
      timestamp: block.block_header.raw_data.timestamp },
    flags,
    simulationOwner: block.block_header.raw_data.witness_address,
  };
}

export function assessObservation(parsed, active, expectedOutputHex) {
  if (active) {
    assert.equal(parsed.returnDataLength, 32, "active precompile returned no word");
    assert.equal(parsed.outputHex, expectedOutputHex, "precompile word mismatch");
    return "PASS_ACTIVE_PRECOMPILE";
  }
  assert.equal(parsed.returnDataLength, 0, "disabled precompile unexpectedly returned data");
  return "PASS_INACTIVE_DISPATCH_ONLY";
}

function main() {
  const build = process.env.CONFORMANCE_BUILD_DIR || path.join(ROOT, "build");
  const output = path.join(build, "reports/nile.json");
  const evidence = path.join(build, "nile-evidence");
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.mkdirSync(evidence, { recursive: true });
  const report = { status: "RUNNING", endpoint: ENDPOINT,
    observationType: "NILE_READ_ONLY_TVM_SIMULATION", broadcasts: 0,
    limitation: "Node execution against live chain state; NOT a mined transaction, consensus replay, or full PQ transaction/block/P2P validation. Calls use moving head state, not a pinned historical block.",
    implementationCommit: JSON.parse(fs.readFileSync(path.join(ROOT, "SOURCE_LOCK.json"))).referenceImplementation.commit,
    runnerSha256: sha256(fs.readFileSync(fileURLToPath(import.meta.url))),
    observations: [], notRun: [],
  };
  try {
    const genesis = request("/wallet/getblockbynum", { num: 0 });
    assert.equal(genesis.blockID, NILE_GENESIS, "refusing non-Nile chain");
    report.genesisBlockId = genesis.blockID;
    report.before = snapshot();
    for (const name of ["fn-dsa-512", "ml-dsa-44"]) {
      const file = fs.readFileSync(path.join(ROOT, "fixtures", `${name}.json`));
      const fixture = JSON.parse(file);
      const key = name === "fn-dsa-512" ? "getAllowFnDsa512" : "getAllowMlDsa44";
      const active = report.before.flags[key].value === 1;
      for (const c of precompileCases(fixture)) {
        if (!active && c.id !== "valid") {
          report.notRun.push({ scheme: name, case: c.id, reason: "SCHEME_INACTIVE" });
          continue;
        }
        const bytecode = buildProbe(fixture.precompile.address, c.input);
        const body = { owner_address: report.before.simulationOwner, data: bytecode.toString("hex"), visible: false };
        const response = request("/wallet/triggerconstantcontract", body);
        fs.writeFileSync(path.join(evidence, `${name}-${c.id}.json`), JSON.stringify({ request: body, response }, null, 2) + "\n");
        const parsed = parseProbeResult(response);
        const status = assessObservation(parsed, active, c.expectedOutputHex);
        report.observations.push({ scheme: name, case: c.id, at: new Date().toISOString(),
          fixtureSha256: sha256(file), inputSha256: sha256(c.input), inputLength: c.input.length,
          probeBytecodeSha256: sha256(bytecode), address: fixture.precompile.address,
          activationFlag: report.before.flags[key], expectedOutputWhenActiveHex: c.expectedOutputHex,
          observed: parsed, status, energyUsed: response.energy_used,
        });
        console.log(`${name}/${c.id}: ${status} returnBytes=${parsed.returnDataLength}`);
      }
      if (!active) report.notRun.push({ scheme: name, case: "valid-signature-verification", reason: "SCHEME_INACTIVE; empty return is not cryptographic verification" });
    }
    report.after = snapshot();
    assert.equal(report.before.nodeVersion, report.after.nodeVersion, "node version changed during run");
    assert.deepEqual(report.before.flags, report.after.flags, "activation flags changed during run");
    report.status = report.notRun.length ? "PASS_WITH_INACTIVE_SCHEME_LIMITATION" : "PASS";
  } catch (error) {
    report.status = "FAIL_OR_UNVERIFIED";
    report.error = error.message;
    process.exitCode = 1;
  }
  fs.writeFileSync(output, JSON.stringify(report, null, 2) + "\n");
  console.log(`Nile report: ${report.status} (${output})`);
  if (report.error) console.error(report.error);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
