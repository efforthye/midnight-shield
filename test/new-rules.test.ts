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
