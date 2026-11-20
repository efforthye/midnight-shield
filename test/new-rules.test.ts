import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { lintSource } from "../src/linter.js";
import { HEADER } from "./helpers.js";

const ids = (src: string, file = "c.compact") => lintSource(src, file).map((f) => f.ruleId);
const has = (src: string, id: string, file?: string) => ids(src, file).includes(id);

const OWNED = `${HEADER}
export ledger ownerId: Bytes<32>;
export ledger admins: Set<Bytes<32>>;
export ledger count: Counter;
witness secretKey(): Bytes<32>;
circuit idOf(sk: Bytes<32>): Bytes<32> {
  return persistentHash<Vector<2, Bytes<32>>>([pad(32, "t:id:"), sk]);
}
export circuit onlyOwner(): [] {
  assert(idOf(secretKey()) == ownerId, "not the owner");
}
export circuit onlyAdmin(): [] {
  assert(admins.member(disclose(idOf(secretKey()))), "not an admin");
}
`;

describe("MS011 unguarded-auth-update", () => {
  it("flags an exported circuit that replaces the owner without a check", () => {
    assert.ok(has(`${OWNED}
export circuit setOwner(id: Bytes<32>): [] {
  ownerId = disclose(id);
}`, "MS011"));
  });

  it("flags adding to an admin allow-list without a check", () => {
    assert.ok(has(`${OWNED}
export circuit addAdmin(id: Bytes<32>): [] {
  admins.insert(disclose(id));
}`, "MS011"));
  });

  it("follows the write into a helper circuit", () => {
    assert.ok(has(`${OWNED}
circuit store(id: Bytes<32>): [] {
  ownerId = disclose(id);
}
export circuit setOwner(id: Bytes<32>): [] {
  store(id);
}`, "MS011"));
  });

  it("does not flag when the circuit, or a helper it calls, asserts", () => {
    assert.ok(!has(`${OWNED}
export circuit transfer(id: Bytes<32>): [] {
  assert(idOf(secretKey()) == ownerId, "not the owner");
  ownerId = disclose(id);
}`, "MS011"));
    assert.ok(!has(`${OWNED}
circuit requireOwner(): [] {
  assert(idOf(secretKey()) == ownerId, "not the owner");
}
export circuit transfer(id: Bytes<32>): [] {
  requireOwner();
  ownerId = disclose(id);
}`, "MS011"));
  });

  it("does not flag the constructor, fields not used for authorization, or calls into other modules", () => {
    assert.ok(!has(`${OWNED}
constructor() {
  ownerId = disclose(idOf(secretKey()));
}
export circuit increment(): [] {
  count.increment(1);
}`, "MS011"));
    assert.ok(!has(`${OWNED}
export circuit transfer(id: Bytes<32>): [] {
  Ownable_assertOnlyOwner();
  ownerId = disclose(id);
}`, "MS011"));
  });

  it("does not treat state-machine checks as authorization", () => {
    assert.ok(!has(`${HEADER}
enum State { OPEN, CLOSED }
export ledger state: State;
export circuit close(): [] {
  state = State.CLOSED;
}
export circuit check(): [] {
  assert(state == State.OPEN, "closed");
}`, "MS011"));
  });
});

describe("MS103 hardcoded-secret", () => {
  const KEY = "9f3c2a7e5b1d4c8f6a0e2b9d7c5f1a3e8b6d4f2a0c9e7b5d3f1a8c6e4b2d0f97";

  it("flags a hex key or a recovery phrase assigned to a secret name", () => {
    assert.ok(has(`const seed = "${KEY}";`, "MS103", "a.ts"));
    assert.ok(has(`export const cfg = { secretKey: '0x${KEY}' };`, "MS103", "a.ts"));
    assert.ok(has(`const mnemonic = "orbit velvet hammer cabin lunar fossil drift spice anchor meadow tribe quiz";`, "MS103", "a.ts"));
  });

  it("does not flag development seeds, test phrases, other names, values from the environment, or test files", () => {
    assert.ok(!has(`const seed = "0000000000000000000000000000000000000000000000000000000000000001";`, "MS103", "a.ts"));
    assert.ok(!has(`const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";`, "MS103", "a.ts"));
    assert.ok(!has(`const txHash = "${KEY}";`, "MS103", "a.ts"));
    assert.ok(!has(`const seed = process.env.SEED ?? "";`, "MS103", "a.ts"));
    assert.ok(!has(`const seed = "${KEY}";`, "MS103", "test/a.test.ts"));
  });
});

describe("MS104 private-state-in-browser-storage", () => {
  it("flags private state or secrets written to localStorage or sessionStorage", () => {
    assert.ok(has(`localStorage.setItem("app-private-state", JSON.stringify(state));`, "MS104", "a.ts"));
    assert.ok(has(`sessionStorage.setItem(KEY, JSON.stringify(privateState));`, "MS104", "a.ts"));
    assert.ok(has(`localStorage.secretKey = sk;`, "MS104", "a.ts"));
    assert.ok(has(`localStorage["seed"] = value;`, "MS104", "a.ts"));
  });

  it("does not flag reads or harmless values", () => {
    assert.ok(!has(`localStorage.setItem("theme", theme);`, "MS104", "a.ts"));
    assert.ok(!has(`const s = localStorage.getItem("privateState");`, "MS104", "a.ts"));
    assert.ok(!has(`if (localStorage.length == 0) {}`, "MS104", "a.ts"));
  });
});

const STATE = `${HEADER}
export ledger stored: Bytes<32>;
export ledger sealed: Bytes<32>;
export ledger salt: Bytes<32>;
witness secretKey(): Bytes<32>;
witness isAdmin(): Boolean;
witness approved(): Boolean;
witness bidRandomness(): Bytes<32>;
`;

describe("MS012 transient-hash-in-state", () => {
  it("flags a transient hash or commitment written to the ledger, also through a local", () => {
    assert.ok(has(`${STATE}
export circuit f(): [] {
  stored = disclose(transientHash<Bytes<32>>(secretKey()));
}`, "MS012"));
    assert.ok(has(`${STATE}
export circuit f(): [] {
  const h = transientCommit<Bytes<32>>(secretKey(), bidRandomness());
  stored = disclose(h);
}`, "MS012"));
  });

  it("does not flag persistent hashes or transient ones used only in checks", () => {
    assert.ok(!has(`${STATE}
export circuit f(): [] {
  stored = disclose(persistentHash<Bytes<32>>(secretKey()));
}`, "MS012"));
    assert.ok(!has(`${STATE}
export circuit f(x: Bytes<32>): [] {
  assert(transientHash<Bytes<32>>(x) == transientHash<Bytes<32>>(secretKey()), "bad");
}`, "MS012"));
  });
});

describe("MS013 witness-controlled-assert", () => {
  it("flags an assert on a Boolean witness, negated, compared with a literal, or through a local", () => {
    for (const cond of ["disclose(isAdmin())", "!disclose(isAdmin())", "disclose(isAdmin() == true)", "disclose(isAdmin() && approved())"]) {
      assert.ok(has(`${STATE}
export circuit f(): [] {
  assert(${cond}, "no");
}`, "MS013"), cond);
    }
    assert.ok(has(`${STATE}
export circuit f(): [] {
  const ok = isAdmin();
  assert(disclose(ok), "no");
}`, "MS013"));
  });

  it("does not flag asserts that also check something the contract trusts", () => {
    assert.ok(!has(`${STATE}
export circuit f(): [] {
  assert(disclose(isAdmin() && persistentHash<Bytes<32>>(secretKey()) == stored), "no");
}`, "MS013"));
    assert.ok(!has(`${STATE}
export circuit f(): [] {
  assert(disclose(persistentHash<Bytes<32>>(secretKey()) == stored), "no");
}`, "MS013"));
  });
});

describe("MS014 commitment-randomness-disclosed", () => {
  const COMMIT = `export circuit bid(v: Uint<64>): [] {
  sealed = disclose(persistentCommit<Uint<64>>(v, bidRandomness()));
}`;
  it("flags commitment randomness made public", () => {
    assert.ok(has(`${STATE}${COMMIT}
export circuit leak(): [] {
  salt = disclose(bidRandomness());
}`, "MS014"));
  });

  it("does not flag opening the commitment in an assert, or witnesses not used as randomness", () => {
    assert.ok(!has(`${STATE}${COMMIT}
export circuit reveal(v: Uint<64>): [] {
  const r = bidRandomness();
  assert(disclose(persistentCommit<Uint<64>>(v, r) == sealed), "no match");
  salt = disclose(r);
}`, "MS014"));
    assert.ok(!has(`${STATE}${COMMIT}
export circuit pub(): [] {
  stored = disclose(persistentHash<Bytes<32>>(secretKey()));
}`, "MS014"));
  });
});

describe("MS105 insecure-randomness", () => {
  it("flags Math.random() used for secrets, nonces or salts", () => {
    assert.ok(has(`const salt = Math.random().toString(16);`, "MS105", "a.ts"));
    assert.ok(has(`const state = { secretKey: Math.random() * 1e18 };`, "MS105", "a.ts"));
    assert.ok(has(`function newNonce() { return Math.floor(Math.random() * 2 ** 32); }`, "MS105", "a.ts"));
  });

  it("does not flag Math.random() for UI values", () => {
    assert.ok(!has(`const delay = Math.random() * 1000;`, "MS105", "a.ts"));
    assert.ok(!has(`const color = colors[Math.floor(Math.random() * colors.length)];`, "MS105", "a.ts"));
    assert.ok(!has(`const salt = crypto.getRandomValues(new Uint8Array(32));`, "MS105", "a.ts"));
  });
});

describe("MS106 secret-sent-over-network", () => {
  it("flags a secret in a URL, a request body or a client call", () => {
    assert.ok(has("await fetch(`https://x.com/save?seed=${seed}`);", "MS106", "a.ts"));
    assert.ok(has(`await fetch(url, { body: JSON.stringify({ secretKey }) });`, "MS106", "a.ts"));
    assert.ok(has(`await axios.post("/backup", { mnemonic });`, "MS106", "a.ts"));
  });

  it("does not flag values derived from a secret, or non-secret data", () => {
    assert.ok(!has(`await fetch(url, { body: JSON.stringify({ publicKey: publicKeyOf(seed) }) });`, "MS106", "a.ts"));
    assert.ok(!has(`await fetch(url, { body: JSON.stringify({ hash: hashSecret(secretKey) }) });`, "MS106", "a.ts"));
    assert.ok(!has(`await fetch(url, { body: JSON.stringify({ address, amount }) });`, "MS106", "a.ts"));
  });
});

describe("MS011 and commit-reveal", () => {
  it("does not treat opening a commitment as a caller check", () => {
    assert.ok(!has(`${STATE}
export circuit bid(v: Uint<64>): [] {
  sealed = disclose(persistentCommit<Uint<64>>(v, bidRandomness()));
}
export circuit reveal(v: Uint<64>): [] {
  assert(disclose(persistentCommit<Uint<64>>(v, bidRandomness()) == sealed), "no match");
}`, "MS011"));
  });
});

const C = (body: string) => `${HEADER}
export ledger round: Uint<32>;
export ledger total: Field;
export ledger used: Set<Bytes<32>>;
export ledger tree: MerkleTree<10, Bytes<32>>;
export ledger owner: Bytes<32>;
witness secretKey(): Bytes<32>;
witness nonce(): Bytes<32>;
export circuit idOf(sk: Bytes<32>): Bytes<32> {
  return persistentHash<Vector<2, Bytes<32>>>([pad(32, "t:id:"), sk]);
}
${body}`;

describe("MS015–MS032", () => {
  const cases: [string, string, string][] = [
    // rule, flagged, not flagged
    ["MS015", `witness unusedThing(): Field;\nexport circuit f(): [] { assert(idOf(secretKey()) == owner, "x"); }`, `export circuit f(): [] { assert(idOf(secretKey()) == owner, "x"); const n = nonce(); }`],
    ["MS016", `circuit helper(): Field { return 1; }`, `circuit helper(): Field { return 1; }\nexport circuit f(): Field { return helper(); }`],
    ["MS017", `export circuit f(x: Uint<8>): [] { assert(disclose(x) >= 0, "x"); }`, `export circuit f(x: Uint<8>): [] { assert(disclose(x) > 0, "x"); }`],
    ["MS018", `export circuit f(): [] { used.insert(disclose(idOf(secretKey()))); }`, `export circuit f(): [] { const n = disclose(idOf(secretKey())); assert(!used.member(n), "x"); used.insert(n); }`],
    ["MS019", `export circuit f(a: Uint<64>, to: UserAddress): [] { sendUnshielded(default<Bytes<32>>, disclose(a) as Uint<128>, right<ContractAddress, UserAddress>(disclose(to))); }`, `export circuit f(a: Uint<64>, to: UserAddress): [] { assert(idOf(secretKey()) == owner, "x"); sendUnshielded(default<Bytes<32>>, disclose(a) as Uint<128>, right<ContractAddress, UserAddress>(disclose(to))); }`],
    ["MS020", `export circuit f(a: Uint<64>, to: UserAddress): [] { mintUnshieldedToken(pad(32, "t:"), disclose(a), right<ContractAddress, UserAddress>(disclose(to))); }`, `export circuit _f(a: Uint<64>, to: UserAddress): [] { mintUnshieldedToken(pad(32, "t:"), disclose(a), right<ContractAddress, UserAddress>(disclose(to))); }`],
    ["MS021", `export circuit j(): [] { tree.insert(disclose(persistentHash<Vector<2, Bytes<32>>>([pad(32, "t:m:"), secretKey()]))); }\nexport circuit v(): [] { const n = disclose(persistentHash<Vector<2, Bytes<32>>>([pad(32, "t:m:"), secretKey()])); assert(!used.member(n), "x"); used.insert(n); }`, `export circuit j(): [] { tree.insert(disclose(persistentHash<Vector<2, Bytes<32>>>([pad(32, "t:m:"), secretKey()]))); }\nexport circuit v(): [] { const n = disclose(persistentHash<Vector<2, Bytes<32>>>([pad(32, "t:n:"), secretKey()])); assert(!used.member(n), "x"); used.insert(n); }`],
    ["MS022", `export circuit f(round: Uint<32>): [] { assert(disclose(round) > 0, "x"); }`, `export circuit f(r: Uint<32>): [] { assert(disclose(r) > 0, "x"); }`],
    ["MS023", `export circuit f(v: Uint<8>): [] { owner = disclose(persistentCommit<Uint<8>>(v, secretKey())); assert(true || false, "x"); }`, `export circuit f(v: Uint<8>): [] { assert(idOf(secretKey()) == owner, "x"); owner = disclose(persistentCommit<Uint<8>>(v, nonce())); }`],
    ["MS024", `export circuit f(): [] { if (true) { round = 1; } }`, `export circuit f(x: Boolean): [] { if (disclose(x)) { round = 1; } else { assert(false, "rejected"); } }`],
    ["MS025", `export circuit f(): [] { round = 1; round = 2; }`, `export circuit f(): [] { round = 1; round = round + 1; }`],
    ["MS026", `export circuit f(persistentHash: Field): Field { return disclose(persistentHash); }`, `export circuit f(p: Field): Field { return disclose(p); }`],
    ["MS027", `export circuit f(): [] { used.member(disclose(idOf(secretKey()))); }`, `export circuit f(): [] { assert(used.member(disclose(idOf(secretKey()))), "x"); }`],
    ["MS029", `export circuit f(r: Uint<32>): [] { disclose(r) == round; }`, `export circuit f(r: Uint<32>): [] { assert(disclose(r) == round, "x"); }`],
    ["MS031", `export circuit f(a: Field): [] { total = total + disclose(a); }`, `export circuit f(a: Field): [] { total = disclose(a); }`],
    ["MS032", `export circuit f(): [] { const x = idOf(secretKey()); }`, `export circuit f(): [] { const x = idOf(secretKey()); assert(x == owner, "x"); }`],
  ];
  for (const [id, bad, good] of cases) {
    it(`${id}: flags the vulnerable case and not the safe one`, () => {
      assert.ok(has(C(bad), id), `${id} missed:\n${bad}`);
      assert.ok(!has(C(good), id), `${id} false positive:\n${good}`);
    });
  }

  it("MS028: flags receiving without any send, not a contract that can pay out", () => {
    const recv = `export circuit d(c: ShieldedCoinInfo): [] { receiveShielded(disclose(c)); }`;
    assert.ok(has(C(recv), "MS028"));
    assert.ok(!has(C(`${recv}\nexport circuit w(i: QualifiedShieldedCoinInfo, k: ZswapCoinPublicKey, v: Uint<128>): [] { assert(idOf(secretKey()) == owner, "x"); sendShielded(disclose(i), left<ZswapCoinPublicKey, ContractAddress>(disclose(k)), disclose(v)); }`), "MS028"));
  });

  it("MS030: flags invisible direction characters in Compact and TypeScript", () => {
    assert.ok(has(C(`// admin only ‮ } ⁦ if (isAdmin) ⁩ ⁦ begin`), "MS030"));
    assert.ok(has(`const ok = true; // ⁧ check ⁩`, "MS030", "a.ts"));
    assert.ok(!has(`const ok = true; // 안녕하세요 مرحبا`, "MS030", "a.ts"));
  });

  it("MS011: an owner field nobody checks yet is still caught, with low confidence", () => {
    const f = lintSource(C(`export circuit setOwner(k: Bytes<32>): [] { owner = disclose(k); }`), "c.compact").find((x) => x.ruleId === "MS011");
    assert.equal(f?.confidence, "low");
  });
});

describe("MS107–MS112", () => {
  const cases: [string, string, string][] = [
    ["MS107", `new https.Agent({ rejectUnauthorized: false });`, `new https.Agent({ rejectUnauthorized: true });`],
    ["MS107", `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";`, `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";`],
    ["MS108", `eval(code);`, `redis.eval(script);`],
    ["MS108", `const f = new Function("a", body);`, `const f = function () {};`],
    ["MS109", `const indexerUri = "http://indexer.example.com/api";`, `const indexerUri = "https://indexer.example.com/api";`],
    ["MS109", `const nodeWs = "ws://rpc.example.org";`, `const nodeWs = "ws://localhost:9944";`],
    ["MS110", "throw new Error(`bad seed ${seed}`);", "throw new Error(`Set ${seedEnv} in .env`);"],
    ["MS111", `fs.writeFileSync(file, seed);`, `fs.writeFileSync(file, seed, { mode: 0o600 });`],
    ["MS112", `win.postMessage(data, "*");`, `win.postMessage(data, "https://app.example.com");`],
  ];
  for (const [id, bad, good] of cases) {
    it(`${id}: ${bad}`, () => {
      assert.ok(has(bad, id, "a.ts"), `${id} missed: ${bad}`);
      assert.ok(!has(good, id, "a.ts"), `${id} false positive: ${good}`);
    });
  }
});

describe("MS033 unsupported-language-version", () => {
  const src = (pragma: string) => `pragma language_version ${pragma};\nimport CompactStandardLibrary;\nexport ledger x: Uint<8>;\nexport circuit f(): [] { x = 1; }\n`;
  it("warns when the pragma only allows versions outside the tested range", () => {
    assert.ok(has(src(">= 0.30.0"), "MS033"));
    assert.ok(has(src("0.31"), "MS033"));
    assert.ok(has(src("0.12"), "MS033"));
  });
  it("is quiet for tested versions and open ranges that include them", () => {
    for (const p of [">= 0.28.0", "0.28", ">= 0.16.0", ">= 0.25.0", ">= 0.22 && <= 0.28"]) assert.ok(!has(src(p), "MS033"), p);
  });
});

describe("DApp secrets tracked by where they come from", () => {
  it("treats aliases of secret properties and generator results as secrets", () => {
    assert.ok(has("const k = privateState.secretKey;\nconsole.log(`key ${k}`);", "MS102", "a.ts"));
    assert.ok(has("const words = generateMnemonic();\nawait fetch(`/backup?w=${words}`);", "MS106", "a.ts"));
    assert.ok(has("const m = await wallet.exportSeed();\nconst hex = toHex(m);\nSentry.setContext(\"w\", { hex });", "MS117", "a.ts"));
    assert.ok(has("const { secretKey: k } = privateState;\nlocalStorage.setItem(\"x\", k);", "MS104", "a.ts"));
  });
  it("does not treat values derived through other functions as secrets", () => {
    assert.ok(!has("const k = privateState.secretKey;\nconst pk = publicKeyOf(k);\nconsole.log(pk);", "MS102", "a.ts"));
    assert.ok(!has("const file = stateFileFor(env.networkId, seeds.masterSeed);\nlogger.warn(`no ${file}`);", "MS102", "a.ts"));
  });
});
