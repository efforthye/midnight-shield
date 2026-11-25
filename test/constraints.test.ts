import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { lintSource, mapConstraints } from "../src/linter.js";
import { formatConstraints, formatConstraintsMarkdown } from "../src/reporters.js";
import { HEADER } from "./helpers.js";

const report = (src: string) => mapConstraints(HEADER + src, "c.compact");
const input = (src: string, circuit: string, name: string) => report(src).find((c) => c.name === circuit)?.inputs.find((i) => i.name === name);
const ids = (src: string) => lintSource(HEADER + src, "c.compact").map((f) => f.ruleId);

describe("witness constraint report", () => {
  it("follows a witness into the ledger and a transfer", () => {
    const src = `export ledger total: Uint<128>;
witness bonus(): Uint<128>;
export circuit pay(): [] {
  const b = disclose(bonus());
  total = b;
  sendUnshielded(default<Bytes<32>>, b, right<ContractAddress, UserAddress>(default<UserAddress>));
}`;
    const i = input(src, "pay", "bonus()")!;
    assert.deepEqual(i.reaches, ["total", "sendUnshielded amount"]);
    assert.deepEqual(i.constraints, []);
    assert.match(formatConstraints(report(src), { color: false }), /bonus\(\)\s+FREE/);
  });

  it("classifies each constraint", () => {
    const src = `export ledger price: Uint<64>;
export ledger members: Set<Bytes<32>>;
export ledger n: Counter;
witness p(): Uint<64>;
witness id(): Bytes<32>;
witness age(): Uint<8>;
witness sk(): Bytes<32>;
export circuit go(publicId: Bytes<32>): [] {
  assert(p() == price, "price");
  assert(members.member(disclose(id())), "member");
  assert(age() >= 18, "age");
  assert(persistentHash<Vector<2, Bytes<32>>>([pad(32, "t:"), sk()]) == publicId, "id");
  n.increment(1);
}`;
    const kinds = (n: string) => input(src, "go", n)!.constraints.map((c) => c.kind);
    assert.deepEqual(kinds("p()"), ["tied to ledger"]);
    assert.deepEqual(kinds("id()"), ["membership"]);
    assert.deepEqual(kinds("age()"), ["bounded by constant"]);
    assert.deepEqual(kinds("sk()"), ["hash or signature"]);
  });

  it("marks a witness that only reaches state hashed as a secret", () => {
    const src = `export ledger commitments: Set<Bytes<32>>;
witness sk(): Bytes<32>;
export circuit register(): [] {
  commitments.insert(disclose(persistentHash<Vector<2, Bytes<32>>>([pad(32, "t:"), sk()])));
}`;
    const i = input(src, "register", "sk()")!;
    assert.equal(i.hashedOnly, true);
    assert.deepEqual(i.reaches, ["commitments (hashed)"]);
    assert.match(formatConstraints(report(src), { color: false }), /sk\(\)\s+secret/);
    assert.match(formatConstraintsMarkdown(report(src)), /\| `sk\(\)` \| secret \|/);
  });

  it("binds helper parameters to the caller's arguments", () => {
    const src = `export ledger price: Uint<64>;
export ledger n: Counter;
witness p(): Uint<64>;
circuit checkPrice(x: Uint<64>): [] { assert(x == price, "stale"); }
export circuit go(): [] { checkPrice(p()); n.increment(1); }`;
    assert.deepEqual(input(src, "go", "p()")!.constraints.map((c) => c.kind), ["tied to ledger"]);
  });
});

describe("MS037 self-satisfiable-check", () => {
  it("flags a comparison of prover-chosen values only", () => {
    assert.ok(ids(`export ledger n: Counter;
witness rating(): Uint<16>;
export circuit prove(threshold: Uint<16>): [] {
  assert(rating() >= threshold, "low");
  n.increment(1);
}`).includes("MS037"));
  });
  it("stays quiet when one value is anchored, bounded by a constant, hashed, or the circuit changes nothing", () => {
    const quiet = (body: string) => assert.ok(!ids(body).includes("MS037"), body);
    quiet(`export ledger oracle: Uint<64>;
export ledger debt: Uint<128>;
witness price(): Uint<64>;
export circuit borrow(a: Uint<64>, c: Uint<64>): [] {
  const p = price();
  assert(p == oracle, "stale");
  assert(disclose(c) * p >= disclose(a), "under");
  debt = disclose(a);
}`);
    quiet(`export ledger n: Counter;
witness age(): Uint<8>;
export circuit prove(): [] { assert(age() >= 18, "young"); n.increment(1); }`);
    quiet(`export ledger n: Counter;
witness sk(): Bytes<32>;
export circuit prove(id: Bytes<32>): [] { assert(persistentHash<Vector<2, Bytes<32>>>([pad(32, "t:"), sk()]) == id, "no"); n.increment(1); }`);
    quiet(`witness rating(): Uint<16>;
export circuit check(threshold: Uint<16>): Boolean { assert(rating() >= threshold, "low"); return true; }`);
  });
  it("leaves an assert on a witness Boolean to MS013", () => {
    const found = ids(`export ledger n: Counter;
witness ok(a: Uint<16>): Boolean;
export circuit go(a: Uint<16>): [] { assert(ok(a), "no"); n.increment(1); }`);
    assert.ok(found.includes("MS013"));
    assert.ok(!found.includes("MS037"));
  });
});
