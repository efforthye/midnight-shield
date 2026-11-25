import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mapAccessInFiles } from "../src/node.js";
import { lintSource, mapAccess } from "../src/linter.js";
import { formatAccess, formatAccessMarkdown } from "../src/reporters.js";
import { HEADER } from "./helpers.js";

const OWNER = `export ledger ownerId: Bytes<32>;
witness secretKey(): Bytes<32>;
circuit deriveId(sk: Bytes<32>): Bytes<32> {
  return persistentHash<Vector<2, Bytes<32>>>([pad(32, "t:owner:"), sk]);
}
`;
const access = (src: string) => mapAccess(HEADER + src, "c.compact");
const who = (src: string, name: string) => access(src).find((c) => c.name === name)?.who;
const ids = (src: string) => lintSource(HEADER + src, "c.compact").map((f) => f.ruleId);

describe("access map", () => {
  it("a hash of the caller's secret compared with stored state restricts the caller", () => {
    const src = OWNER + `export ledger fee: Uint<64>;
export circuit setFee(f: Uint<64>): [] {
  const me = deriveId(secretKey());
  assert(me == ownerId, "not owner");
  fee = disclose(f);
}`;
    const [c] = access(src);
    assert.equal(c.who, "restricted");
    assert.deepEqual(c.guards.map((g) => [g.kind, g.via]), [["secret", undefined]]);
    assert.deepEqual(c.writes.map((w) => w.field), ["fee"]);
  });

  it("the check may live in a helper circuit", () => {
    const src = OWNER + `export ledger fee: Uint<64>;
circuit onlyOwner(): [] { assert(deriveId(secretKey()) == ownerId, "not owner"); }
export circuit setFee(f: Uint<64>): [] { onlyOwner(); fee = disclose(f); }`;
    const [c] = access(src);
    assert.equal(c.who, "restricted");
    assert.equal(c.guards[0].via, "onlyOwner");
  });

  it("ownPublicKey(), a witness result and an unbound Merkle path are checks anyone can pass", () => {
    const src = `export ledger owner: ZswapCoinPublicKey;
export ledger members: MerkleTree<10, Bytes<32>>;
export ledger n: Counter;
witness isAdmin(): Boolean;
witness path(): MerkleTreePath<10, Bytes<32>>;
export circuit a(): [] { assert(ownPublicKey() == owner, "no"); n.increment(1); }
export circuit b(): [] { assert(isAdmin(), "no"); n.increment(1); }
export circuit c(): [] { assert(members.checkRoot(disclose(merkleTreePathRoot<10, Bytes<32>>(path()))), "no"); n.increment(1); }`;
    assert.equal(who(src, "a"), "bypassable");
    assert.equal(who(src, "b"), "bypassable");
    assert.equal(who(src, "c"), "bypassable");
  });

  it("ownPublicKey() hashed together with a secret is as strong as the secret", () => {
    const src = `export ledger ownerHash: Bytes<32>;
witness secretKey(): Bytes<32>;
export circuit cancel(): [] {
  assert(persistentHash<Vector<2, Bytes<32>>>([ownPublicKey().bytes, secretKey()]) == ownerHash, "no");
  ownerHash = default<Bytes<32>>;
}`;
    assert.equal(who(src, "cancel"), "restricted");
  });

  it("a stored id compared with a publicKey(secret, counter) that also reads the ledger is still a secret check", () => {
    const src = `export ledger owner: Bytes<32>;
export ledger sequence: Counter;
witness localSecretKey(): Bytes<32>;
circuit publicKey(sk: Bytes<32>, seq: Bytes<32>): Bytes<32> {
  return persistentHash<Vector<3, Bytes<32>>>([pad(32, "bboard:pk:"), seq, sk]);
}
export circuit takeDown(): [] {
  assert(owner == publicKey(localSecretKey(), sequence as Field as Bytes<32>), "not the owner");
  sequence.increment(1);
}`;
    assert.equal(who(src, "takeDown"), "restricted");
  });

  it("a nullifier check limits how often, not who", () => {
    const src = `export ledger used: Set<Bytes<32>>;
witness secretKey(): Bytes<32>;
export circuit act(): [] {
  const n = disclose(persistentHash<Vector<2, Bytes<32>>>([pad(32, "t:n:"), secretKey()]));
  assert(!used.member(n), "used");
  used.insert(n);
}`;
    const [c] = access(src);
    assert.equal(c.who, "anyone");
    assert.equal(c.guards[0].kind, "one-time");
  });

  it("an imported check counts, but is labelled as such", () => {
    const src = `import "./Ownable" prefix Ownable_;
export ledger paused: Boolean;
export circuit pause(): [] { Ownable_assertOnlyOwner(); paused = true; }`;
    const [c] = access(src);
    assert.equal(c.who, "imported");
    assert.equal(c.guards[0].callee, "Ownable_assertOnlyOwner");
  });

  it("reads an imported module to see what its check really does", () => {
    const dir = mkdtempSync(join(tmpdir(), "ms-access-"));
    const lib = (body: string) => HEADER + `module Own {\n  export ledger _owner: Bytes<32>;\n  witness sk(): Bytes<32>;\n  export circuit assertOnlyOwner(): [] {\n    ${body}\n  }\n}\n`;
    writeFileSync(join(dir, "Weak.compact"), lib(`assert(ownPublicKey().bytes == _owner, "not owner");`));
    writeFileSync(join(dir, "Strong.compact"), lib(`assert(persistentHash<Vector<2, Bytes<32>>>([pad(32, "o:"), sk()]) == _owner, "not owner");`));
    const app = (lib: string) => HEADER + `import "./${lib}" prefix L_;\nexport ledger fee: Uint<64>;\nexport circuit setFee(f: Uint<64>): [] {\n  L_assertOnlyOwner();\n  fee = disclose(f);\n}\n`;
    writeFileSync(join(dir, "weak.compact"), app("Weak"));
    writeFileSync(join(dir, "strong.compact"), app("Strong"));
    const whoIn = (f: string) => mapAccessInFiles([join(dir, f)], {}, dir).find((c) => c.name === "setFee")?.who;
    assert.equal(whoIn("weak.compact"), "bypassable");
    assert.equal(whoIn("strong.compact"), "restricted");
  });

  it("records token transfers and formats as text and markdown", () => {
    const src = `export circuit pay(a: Uint<128>): [] {
  sendUnshielded(default<Bytes<32>>, disclose(a), right<ContractAddress, UserAddress>(default<UserAddress>));
}`;
    const entries = access(src);
    assert.deepEqual(entries[0].tokens.map((t) => t.op), ["sendUnshielded"]);
    assert.deepEqual(entries[0].findings, ["MS019"]);
    const text = formatAccess(entries, { color: false });
    assert.match(text, /pay\s+anyone\s+-\s+sendUnshielded/);
    assert.match(text, /1 exported circuit: 0 check the caller/);
    assert.match(formatAccessMarkdown(entries), /\| `c.compact` \| pay \| anyone \|/);
  });
});

describe("MS035 inconsistent-guard", () => {
  const base = OWNER + `export ledger fee: Uint<64>;
export circuit setFee(f: Uint<64>): [] {
  assert(deriveId(secretKey()) == ownerId, "not owner");
  fee = disclose(f);
}
`;
  it("flags an unchecked circuit that overwrites a field another circuit protects", () => {
    assert.ok(ids(base + `export circuit resetFee(): [] { fee = 0; }`).includes("MS035"));
    assert.ok(ids(base + `export circuit resetFee(): [] { fee.resetToDefault(); }`).includes("MS035"));
  });
  it("stays quiet when both circuits check, for helpers and for state transitions", () => {
    assert.ok(!ids(base + `export circuit resetFee(): [] { assert(deriveId(secretKey()) == ownerId, "no"); fee = 0; }`).includes("MS035"));
    assert.ok(!ids(base + `export circuit _resetFee(): [] { fee = 0; }`).includes("MS035"));
    assert.ok(!ids(base + `circuit resetFee(): [] { fee = 0; }`).includes("MS035"));
    assert.ok(!ids(base + `export ledger done: Boolean;
export circuit finish(): [] { assert(!done, "done"); done = true; fee = 0; }`).includes("MS035"));
  });
  it("ignores collections, where circuits write different entries", () => {
    const src = OWNER + `export ledger bal: Map<Bytes<32>, Uint<64>>;
export circuit seize(k: Bytes<32>): [] { assert(deriveId(secretKey()) == ownerId, "no"); bal.remove(disclose(k)); }
export circuit deposit(k: Bytes<32>, v: Uint<64>): [] { bal.insert(disclose(k), disclose(v)); }`;
    assert.ok(!ids(src).includes("MS035"));
  });
});

describe("MS036 claimed-identity", () => {
  it("flags a stored owner id compared with a parameter", () => {
    const src = `export ledger ownerId: Uint<32>;
export ledger rate: Uint<64>;
export circuit setRate(callerId: Uint<32>, r: Uint<64>): [] {
  assert(ownerId == disclose(callerId), "only owner");
  rate = disclose(r);
}`;
    assert.ok(ids(src).includes("MS036"));
    assert.equal(access(src)[0].who, "bypassable");
  });
  it("uses the assert message when the field name says nothing", () => {
    const src = `export ledger key: Bytes<32>;
export ledger rate: Uint<64>;
export circuit setRate(k: Bytes<32>, r: Uint<64>): [] {
  assert(key == disclose(k), "not authorized");
  rate = disclose(r);
}`;
    assert.ok(ids(src).includes("MS036"));
  });
  it("stays quiet for hashed parameters, ordinary state checks and module circuits", () => {
    assert.ok(!ids(`export ledger ownerHash: Bytes<32>;
export circuit go(pw: Bytes<32>): [] {
  assert(persistentHash<Vector<2, Bytes<32>>>([pad(32, "t:o:"), pw]) == ownerHash, "only owner");
}`).includes("MS036"));
    assert.ok(!ids(`export ledger round: Uint<32>;
export circuit go(r: Uint<32>): [] { assert(round == disclose(r), "wrong round"); }`).includes("MS036"));
  });
});
