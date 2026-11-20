import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { lintSource } from "../src/linter.js";

const HEADER = "pragma language_version >= 0.28.0;\nimport CompactStandardLibrary;\n";

function ids(source: string): string[] {
  return lintSource(HEADER + source).map((f) => f.ruleId);
}

function count(source: string, id: string): number {
  return ids(source).filter((x) => x === id).length;
}

describe("MS001 own-public-key-auth", () => {
  it("flags ownPublicKey() compared to a stored key", () => {
    const src = `
      export ledger owner: ZswapCoinPublicKey;
      export circuit withdraw(): [] {
        assert(ownPublicKey() == owner, "not owner");
      }`;
    assert.equal(count(src, "MS001"), 1);
  });

  it("flags ownPublicKey() through a local variable and set membership", () => {
    const src = `
      export ledger admins: Set<ZswapCoinPublicKey>;
      export circuit act(): [] {
        const me = ownPublicKey();
        assert(admins.member(me), "not admin");
      }`;
    assert.equal(count(src, "MS001"), 1);
  });

  it("flags ownPublicKey() passed into a helper that compares it", () => {
    const src = `
      export ledger owner: ZswapCoinPublicKey;
      circuit isOwner(pk: ZswapCoinPublicKey): Boolean {
        return pk == owner;
      }
      export circuit act(): [] {
        assert(isOwner(ownPublicKey()), "not owner");
      }`;
    assert.equal(count(src, "MS001"), 1);
  });

  it("does not flag ownPublicKey() used as a payment destination", () => {
    const src = `
      export circuit pay(coin: ShieldedCoinInfo): [] {
        sendImmediateShielded(coin, left<ZswapCoinPublicKey, ContractAddress>(ownPublicKey()), coin.value);
      }`;
    assert.equal(count(src, "MS001"), 0);
  });

  it("does not flag a comparison with a constant (zero-key check)", () => {
    const src = `
      export circuit check(): [] {
        assert(ownPublicKey().bytes != default<Bytes<32>>, "zero key");
      }`;
    assert.equal(count(src, "MS001"), 0);
  });

  it("does not flag ownPublicKey() hashed together with a secret", () => {
    const src = `
      export ledger ownerId: Bytes<32>;
      witness nonce(): Bytes<32>;
      export circuit act(): [] {
        const id = persistentHash<Vector<3, Bytes<32>>>([pad(32, "app:owner"), ownPublicKey().bytes, nonce()]);
        assert(id == ownerId, "not owner");
      }`;
    assert.equal(count(src, "MS001"), 0);
  });
});

describe("MS002 unconstrained-witness", () => {
  it("flags a witness value written to the ledger without any check", () => {
    const src = `
      export ledger balance: Uint<64>;
      witness myBalance(): Uint<64>;
      export circuit sync(): [] {
        balance = disclose(myBalance());
      }`;
    assert.equal(count(src, "MS002"), 1);
  });

  it("does not flag a witness that an assert constrains", () => {
    const src = `
      export ledger balance: Uint<64>;
      witness myBalance(): Uint<64>;
      export circuit sync(): [] {
        const b = myBalance();
        assert(b <= 1000, "too large");
        balance = disclose(b);
      }`;
    assert.equal(count(src, "MS002"), 0);
  });

  it("does not flag randomness or free-form bytes", () => {
    const src = `
      export ledger name: Bytes<32>;
      witness displayName(): Bytes<32>;
      export circuit setName(): [] {
        name = disclose(displayName());
      }`;
    assert.equal(count(src, "MS002"), 0);
  });
});

describe("MS003 low-entropy-hash", () => {
  it("flags a disclosed hash of a private vote", () => {
    const src = `
      export enum Vote { YES, NO }
      export ledger ballots: Set<Bytes<32>>;
      witness myVote(): Vote;
      export circuit cast(): [] {
        const h = persistentHash<Vector<2, Bytes<32>>>([pad(32, "app:vote"), myVote() as Field as Bytes<32>]);
        ballots.insert(disclose(h));
      }`;
    assert.equal(count(src, "MS003"), 1);
  });

  it("flags a disclosed hash of a private age through a helper circuit", () => {
    const src = `
      export ledger ageHash: Bytes<32>;
      circuit hashAge(age: Uint<8>): Bytes<32> {
        return persistentHash<Vector<2, Bytes<32>>>([pad(32, "app:age"), age as Field as Bytes<32>]);
      }
      export circuit register(age: Uint<8>): [] {
        ageHash = disclose(hashAge(age));
      }`;
    assert.equal(count(src, "MS003"), 1);
  });

  it("does not flag when a 32-byte secret is part of the hash", () => {
    const src = `
      export ledger ballots: Set<Bytes<32>>;
      witness sk(): Bytes<32>;
      export circuit cast(choice: Boolean): [] {
        const h = persistentHash<Vector<3, Bytes<32>>>([pad(32, "app:vote"), sk(), choice as Field as Bytes<32>]);
        ballots.insert(disclose(h));
      }`;
    assert.equal(count(src, "MS003"), 0);
  });

  it("does not flag a low-entropy hash that stays private", () => {
    const src = `
      export circuit check(pin: Uint<16>): Boolean {
        const h = persistentHash<Vector<2, Bytes<32>>>([pad(32, "app:pin"), pin as Field as Bytes<32>]);
        return h == h;
      }`;
    assert.equal(count(src, "MS003"), 0);
  });
});

describe("MS004 weak-commitment-randomness", () => {
  it("flags constant randomness", () => {
    const src = `
      export ledger c: Bytes<32>;
      export circuit commit(v: Uint<64>): [] {
        c = persistentCommit<Uint<64>>(v, pad(32, "salt"));
      }`;
    assert.equal(count(src, "MS004"), 1);
  });

  it("flags randomness read from the public ledger", () => {
    const src = `
      export ledger c: Bytes<32>;
      export ledger salt: Bytes<32>;
      export circuit commit(v: Uint<64>): [] {
        c = persistentCommit<Uint<64>>(v, salt);
      }`;
    assert.equal(count(src, "MS004"), 1);
  });

  it("flags short randomness", () => {
    const src = `
      export ledger c: Bytes<32>;
      witness r(): Uint<32>;
      export circuit commit(v: Uint<64>): [] {
        c = persistentCommit<Uint<64>>(v, r() as Field as Bytes<32>);
      }`;
    assert.equal(count(src, "MS004"), 1);
  });

  it("flags randomness reused for two different values", () => {
    const src = `
      export ledger a: Bytes<32>;
      export ledger b: Bytes<32>;
      witness salt(): Bytes<32>;
      export circuit commitBoth(x: Uint<64>, y: Uint<64>): [] {
        const s = salt();
        a = persistentCommit<Uint<64>>(x, s);
        b = persistentCommit<Uint<64>>(y, s);
      }`;
    assert.equal(count(src, "MS004"), 1);
  });

  it("does not flag fresh 32-byte randomness from a witness", () => {
    const src = `
      export ledger c: Bytes<32>;
      witness salt(): Bytes<32>;
      export circuit commit(v: Uint<64>): [] {
        c = persistentCommit<Uint<64>>(v, salt());
      }`;
    assert.equal(count(src, "MS004"), 0);
  });
});

describe("MS005 missing-domain-separation", () => {
  it("flags a hash of a secret with no constant tag", () => {
    const src = `
      export ledger pk: Bytes<32>;
      witness sk(): Bytes<32>;
      export circuit register(): [] {
        pk = disclose(persistentHash<Bytes<32>>(sk()));
      }`;
    assert.equal(count(src, "MS005"), 1);
  });

  it("does not flag a tagged hash", () => {
    const src = `
      export ledger pk: Bytes<32>;
      witness sk(): Bytes<32>;
      export circuit register(): [] {
        pk = disclose(persistentHash<Vector<2, Bytes<32>>>([pad(32, "app:pk"), sk()]));
      }`;
    assert.equal(count(src, "MS005"), 0);
  });

  it("does not flag a helper whose caller passes the tag", () => {
    const src = `
      export ledger pk: Bytes<32>;
      witness sk(): Bytes<32>;
      circuit derive(tag: Bytes<32>, s: Bytes<32>): Bytes<32> {
        return persistentHash<Vector<2, Bytes<32>>>([tag, s]);
      }
      export circuit register(): [] {
        pk = disclose(derive(pad(32, "app:pk"), sk()));
      }`;
    assert.equal(count(src, "MS005"), 0);
  });
});

describe("MS006 missing-pragma", () => {
  it("flags a file without a pragma", () => {
    const findings = lintSource("import CompactStandardLibrary;\nexport ledger x: Uint<8>;\n");
    assert.ok(findings.some((f) => f.ruleId === "MS006"));
  });
});

describe("suppression comments", () => {
  const src = `
      export ledger pk: Bytes<32>;
      witness sk(): Bytes<32>;
      export circuit register(): [] {
        // shield-disable-next-line MS005
        pk = disclose(persistentHash<Bytes<32>>(sk()));
      }`;

  it("hides a finding on the next line", () => {
    assert.equal(count(src, "MS005"), 0);
  });

  it("keeps other rules active", () => {
    const other = src.replace("MS005", "MS001");
    assert.equal(count(other, "MS005"), 1);
  });
});

describe("parser", () => {
  it("parses generics, lambdas, struct literals and ranges without diagnostics", () => {
    const src = `
      export struct Point { x: Field, y: Field }
      export new type Key = Bytes<32>;
      export ledger total: Uint<64>;
      export pure circuit sum(v: Vector<4, Uint<8>>): Uint<64> {
        return fold((acc, x: Uint<8>): Uint<64> => (acc + x) as Uint<64>, 0, v);
      }
      export circuit f(p: Point, n: Uint<0..10>): [] {
        const q = Point { x: p.x, y: p.y };
        for (const i of 0..4) {
          assert(n >= 0 && n < 10, "range");
        }
        const d = default<Bytes<32>>;
        assert(q.x == p.x ? true : false, "eq");
      }`;
    assert.equal(count(src, "MS000"), 0);
  });
});
