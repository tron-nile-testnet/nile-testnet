import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { falcon512 } from '@noble/post-quantum/falcon.js';

const DEFAULT = fileURLToPath(new URL(
  '../../../framework/src/test/resources/pqc/pq-domain-v1.json', import.meta.url));
const vectors = JSON.parse(readFileSync(process.argv[2] ?? DEFAULT, 'utf8'));

const hex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
const toHex = (b) => Buffer.from(b).toString('hex');
const sha256 = (b) => new Uint8Array(createHash('sha256').update(b).digest());

const SCHEMES = {
  FN_DSA_512: {
    publicKey: (seed) => falcon512.keygen(seed).publicKey.slice(1),
    verify: (pk, msg, sig) => falcon512.verify(sig, msg, Uint8Array.of(0x09, ...pk)),
  },
  ML_DSA_44: {
    publicKey: (seed) => ml_dsa44.keygen(seed).publicKey,
    verify: (pk, msg, sig) => ml_dsa44.verify(sig, msg, pk),
  },
};

let failures = 0;
let checked = 0;
const check = (ok, label) => {
  checked++;
  if (!ok) {
    failures++;
    console.error(`FAIL ${label}`);
  }
};

const target = hex(vectors.target);
check(target.length === 32, 'target length');

const bound = {};
for (const d of vectors.domains) {
  const tag = Buffer.from(d.tag, 'ascii');
  const preimage = Uint8Array.of(tag.length, ...tag, ...target);
  bound[d.name] = sha256(preimage);
  check(toHex(preimage) === d.preimage, `${d.name} preimage`);
  check(toHex(bound[d.name]) === d.bound, `${d.name} bound digest`);
}
const domains = Object.keys(bound);
check(domains.length === 4 && new Set(Object.values(bound).map(toHex)).size === 4, 'domains');

for (const s of vectors.schemes) {
  const impl = SCHEMES[s.scheme];
  const pk = hex(s.public_key);
  check(toHex(impl.publicKey(hex(s.seed))) === s.public_key, `${s.scheme} keygen from seed`);
  const seen = new Set();
  for (const c of s.cases) {
    const label = `${s.scheme} ${c.signature} active=${c.active} domain=${c.domain}`;
    const message = c.active ? bound[c.domain] : target;
    const expected = c.active ? c.signature === c.domain : c.signature === 'RAW';
    check(toHex(message) === c.message, `${label} message`);
    check(expected === c.expected, `${label} expected`);
    check(impl.verify(pk, message, hex(s.signatures[c.signature])) === c.expected, label);
    seen.add(`${c.signature}|${c.active}|${c.domain}`);
  }
  for (const sig of ['RAW', ...domains]) {
    check(seen.has(`${sig}|false|null`), `${s.scheme} ${sig} inactive case present`);
    for (const d of domains) {
      check(seen.has(`${sig}|true|${d}`), `${s.scheme} ${sig} under ${d} present`);
    }
  }
  check(s.cases.length === 25, `${s.scheme} case count`);
}

console.log(`${vectors.version} ${checked} checks, ${failures} failures`);
process.exit(failures === 0 ? 0 : 1);
