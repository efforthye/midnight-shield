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
