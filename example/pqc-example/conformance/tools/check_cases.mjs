#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { cryptoCases, precompileCases } from "./cases.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const build = process.env.CONFORMANCE_BUILD_DIR || path.join(root, "build");
const fixtureDir = process.env.CONFORMANCE_FIXTURE_DIR || path.join(root, "fixtures");
const mode = process.argv[2] || "crypto";
assert(["crypto", "extract"].includes(mode), "mode must be crypto or extract");
const classpath = [".cache/bcprov-jdk18on-1.84.jar", ".cache/protobuf-java-3.25.8.jar"].map(f => path.join(root, f)).concat(path.join(build, "java")).join(path.delimiter);
const results = [];
const manifest = [];
function verify(command, args, expected) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.error) throw result.error;
  assert.equal(result.signal, null, "verifier terminated by signal");
  assert.equal(result.status, expected ? 0 : 1, `${command}: ${result.stderr}`);
  assert.match(result.stdout, new RegExp(`^valid=${expected}(?: |$)`, "m"), result.stdout + result.stderr);
}
for (const name of ["fn-dsa-512", "ml-dsa-44"]) {
  const fixture = JSON.parse(fs.readFileSync(path.join(fixtureDir, `${name}.json`), "utf8"));
  for (const c of cryptoCases(fixture)) {
    const dir = path.join(build, "cases", name, c.id);
    fs.mkdirSync(dir, { recursive: true });
    for (const key of ["publicKey", "message", "signature"]) fs.writeFileSync(path.join(dir, `${key}.bin`), c[key]);
    const files = ["publicKey", "message", "signature"].map(key => path.join(dir, `${key}.bin`));
    const bcMode = name === "fn-dsa-512" ? "verify-falcon" : "verify-mldsa";
    if (mode === "crypto") {
      verify("java", ["-cp", classpath, "Tip899BcInterop", bcMode, ...files], c.expectedVerify);
      if (name === "fn-dsa-512") {
        verify(path.join(build, "bin/falcon-ref-cli"), ["verify", ...files], c.expectedReferenceImportVerify ?? c.expectedVerify);
      }
      results.push({ scheme: name, case: c.id, bouncyCastle: "PASS", falconReference: name === "fn-dsa-512" ? "PASS" : "NOT_APPLICABLE", referenceImportException: c.expectedReferenceImportVerify === true });
    }
    manifest.push(["crypto", fixture.scheme.protobufValue, name + "/" + c.id, ...files, c.expectedLengthCheck, c.expectedVerify, fixture.tronAddress.hex].join("\t"));
  }
  for (const c of precompileCases(fixture)) {
    const file = path.join(build, "cases", name, `precompile-${c.id}.bin`);
    fs.writeFileSync(file, c.input);
    manifest.push(["precompile", fixture.scheme.protobufValue, name + "/" + c.id, file, c.expectedOutputHex].join("\t"));
  }
}
fs.mkdirSync(path.join(build, "reports"), { recursive: true });
fs.writeFileSync(path.join(build, "cases/manifest.tsv"), manifest.join("\n") + "\n");
if (mode === "crypto") {
  fs.writeFileSync(path.join(build, "reports/crypto-cases.json"), JSON.stringify({ status: "PASS", scope: "BouncyCastle adapter and Falcon reference import adapter; not protocol or chain execution", cases: results }, null, 2) + "\n");
  console.log(`crypto cases: PASS (${results.length}); protocol/precompile cases extracted separately`);
}
