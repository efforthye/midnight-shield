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

describe("imports", () => {
  it("follows circuits from an imported module and reports at the call site", async () => {
    const { lintFiles } = await import("../src/linter.js");
    const findings = lintFiles(["test/fixtures/imports/main.compact"]);
    const ms001 = findings.filter((f) => f.ruleId === "MS001");
    assert.equal(ms001.length, 1);
    assert.equal(ms001[0].file, "test/fixtures/imports/main.compact");
    assert.equal(ms001[0].line, 9);
  });

  it("counts asserts inside imported circuits as constraints", async () => {
    const { lintFiles } = await import("../src/linter.js");
    const findings = lintFiles(["test/fixtures/imports/main.compact"]);
    assert.equal(findings.filter((f) => f.ruleId === "MS002").length, 0);
  });
});

describe("config", () => {
  it("accepts a valid config", async () => {
    const { validateConfig } = await import("../src/config.js");
    const c = validateConfig({ disable: ["ms005"], failOn: "medium", ignore: ["**/test/**"] });
    assert.deepEqual(c.disable, ["MS005"]);
    assert.equal(c.failOn, "medium");
  });

  it("rejects unknown keys and rule IDs", async () => {
    const { validateConfig } = await import("../src/config.js");
    assert.throws(() => validateConfig({ disabled: ["MS005"] }), /unknown key/);
    assert.throws(() => validateConfig({ disable: ["MS999"] }), /unknown rule/);
  });

  it("skips files matching ignore globs", async () => {
    const { listTargetFiles } = await import("../src/linter.js");
    const all = listTargetFiles(["test/fixtures/imports"]);
    const some = listTargetFiles(["test/fixtures/imports"], ["**/lib/**"]);
    assert.equal(all.length, 2);
    assert.equal(some.length, 1);
  });
});

describe("MS007 disclosed-secret", () => {
  it("flags a secret key witness written to the ledger", () => {
    const src = `
      export ledger k: Bytes<32>;
      witness secretKey(): Bytes<32>;
      export circuit leak(): [] {
        k = disclose(secretKey());
      }`;
    assert.equal(count(src, "MS007"), 1);
  });

  it("flags a secret parameter passed through a local variable", () => {
    const src = `
      export ledger k: Bytes<32>;
      export circuit leak(_secret: Bytes<32>): [] {
        const s = _secret;
        k = disclose(s);
      }`;
    assert.equal(count(src, "MS007"), 1);
  });

  it("does not flag a hash of the secret", () => {
    const src = `
      export ledger k: Bytes<32>;
      witness secretKey(): Bytes<32>;
      export circuit ok(): [] {
        k = disclose(persistentHash<Vector<2, Bytes<32>>>([pad(32, "app:pk"), secretKey()]));
      }`;
    assert.equal(count(src, "MS007"), 0);
  });

  it("does not flag a comparison that involves the secret", () => {
    const src = `
      export ledger ok: Boolean;
      witness secretKey(): Bytes<32>;
      export circuit check(expected: Bytes<32>): [] {
        ok = disclose(secretKey() == expected);
      }`;
    assert.equal(count(src, "MS007"), 0);
  });

  it("does not flag values whose names are not secret", () => {
    const src = `
      export ledger k: Bytes<32>;
      export circuit setKey(pk: Bytes<32>): [] {
        k = disclose(pk);
      }`;
    assert.equal(count(src, "MS007"), 0);
  });
});

describe("isSecretName", () => {
  it("recognizes common secret names", async () => {
    const { isSecretName } = await import("../src/analyzer.js");
    for (const n of ["secretKey", "sk", "localSk", "_secret", "ownerSecretKey", "privateKey", "seed", "wit_ConfidentialTokenSK", "userPin"]) {
      assert.ok(isSecretName(n), n);
    }
    for (const n of ["pk", "publicKey", "skip", "seeded_value_hash", "task", "pinned"]) {
      assert.ok(!isSecretName(n), n);
    }
  });
});

const MERKLE_LEDGER = `
  export ledger members: MerkleTree<10, Bytes<32>>;
  export ledger used: Set<Bytes<32>>;
  export ledger claims: Counter;
  witness secretKey(): Bytes<32>;
  witness memberPath(): MerkleTreePath<10, Bytes<32>>;
  circuit leaf(sk: Bytes<32>): Bytes<32> {
    return persistentHash<Vector<2, Bytes<32>>>([pad(32, "app:leaf"), sk]);
  }`;

describe("MS008 missing-nullifier", () => {
  it("flags a Merkle-authorized state change with no nullifier", () => {
    const src = `${MERKLE_LEDGER}
      export circuit claim(): [] {
        const path = memberPath();
        assert(disclose(path.leaf == leaf(secretKey())), "not yours");
        assert(members.checkRoot(disclose(merkleTreePathRoot<10, Bytes<32>>(path))), "not a member");
        claims.increment(1);
      }`;
    assert.equal(count(src, "MS008"), 1);
  });

  it("does not flag when a nullifier is checked", () => {
    const src = `${MERKLE_LEDGER}
      export circuit claim(): [] {
        const sk = secretKey();
        const path = memberPath();
        assert(disclose(path.leaf == leaf(sk)), "not yours");
        assert(members.checkRoot(disclose(merkleTreePathRoot<10, Bytes<32>>(path))), "not a member");
        const n = disclose(persistentHash<Vector<2, Bytes<32>>>([pad(32, "app:claim"), sk]));
        assert(!used.member(n), "already claimed");
        used.insert(n);
        claims.increment(1);
      }`;
    assert.equal(count(src, "MS008"), 0);
  });

  it("does not flag a read-only membership check", () => {
    const src = `${MERKLE_LEDGER}
      export circuit isMember(): Boolean {
        const path = memberPath();
        assert(disclose(path.leaf == leaf(secretKey())), "not yours");
        assert(members.checkRoot(disclose(merkleTreePathRoot<10, Bytes<32>>(path))), "not a member");
        return true;
      }`;
    assert.equal(count(src, "MS008"), 0);
  });
});

describe("MS009 unbound-merkle-path", () => {
  it("flags a root check without a leaf check", () => {
    const src = `${MERKLE_LEDGER}
      export circuit enter(): [] {
        const path = memberPath();
        assert(members.checkRoot(disclose(merkleTreePathRoot<10, Bytes<32>>(path))), "not a member");
      }`;
    assert.equal(count(src, "MS009"), 1);
  });

  it("follows the root through a variable", () => {
    const src = `${MERKLE_LEDGER}
      export circuit enter(): [] {
        const path = memberPath();
        const root = disclose(merkleTreePathRoot<10, Bytes<32>>(path));
        assert(members.checkRoot(root), "not a member");
      }`;
    assert.equal(count(src, "MS009"), 1);
  });

  it("accepts a leaf check after the root check, or inside an if", () => {
    const after = `${MERKLE_LEDGER}
      export circuit enter(): [] {
        const path = memberPath();
        assert(members.checkRoot(disclose(merkleTreePathRoot<10, Bytes<32>>(path))), "not a member");
        assert(disclose(leaf(secretKey()) == path.leaf), "not yours");
      }`;
    assert.equal(count(after, "MS009"), 0);

    const inIf = `${MERKLE_LEDGER}
      export circuit check(): Boolean {
        const path = memberPath();
        const ok = members.checkRoot(merkleTreePathRoot<10, Bytes<32>>(disclose(path)));
        if (ok) {
          assert(path.leaf == leaf(secretKey()), "not yours");
        }
        return disclose(ok);
      }`;
    assert.equal(count(inIf, "MS009"), 0);
  });
});
