# Writing custom rules

Midnight Shield can load your own rules from plugin modules. Use this for project conventions that are too specific for the built-in rules.

## A plugin

A plugin is an ES module (`.mjs`) whose default export is an array of rules:

```js
// my-rules.mjs
export default [
  {
    id: "ACME001",                  // capital letters, then 3 digits; "MS" is reserved
    name: "no-counter-decrement",
    severity: "low",                // critical | high | medium | low | info
    confidence: "high",             // high | medium | low (default: medium)
    summary: "Our contracts only ever count up.",
    docUrl: "https://example.com/rules/ACME001", // optional
    check(ctx) {
      ctx.visit({
        call(expr, callee, where) {
          if (callee.endsWith(".decrement")) {
            ctx.report({ loc: expr.loc, message: `'${callee}' decrements a counter in '${where.circuit}'.` });
          }
        },
      });
    },
  },
];
```

A working example lives in [`examples/plugins/no-counter-decrement.mjs`](../examples/plugins/no-counter-decrement.mjs).

## Using it

```bash
npx midnight-shield contracts/ --plugin ./my-rules.mjs
```

or in `midnight-shield.config.json` (paths are relative to the config file):

```json
{ "plugins": ["./my-rules.mjs"] }
```

Custom findings work like built-in ones: they appear in every output format (including SARIF), can be suppressed with `// shield-disable-next-line ACME001`, disabled with `"disable": ["ACME001"]`, and recorded in baselines.

## The rule context

| Member | Description |
| --- | --- |
| `ctx.file` | Path of the file being checked, as shown in reports |
| `ctx.source` | The file's text |
| `ctx.program` | The parsed syntax tree (see `src/ast.ts`) |
| `ctx.visit(visitor)` | Walks every circuit, statement and expression |
| `ctx.report({ loc \| line, col?, message, severity?, confidence? })` | Reports a finding |

Visitor callbacks:

| Callback | Called for |
| --- | --- |
| `decl(decl)` | Every top-level and module declaration (`ledger`, `witness`, `circuit`, ...) |
| `circuit(decl, where)` | Every circuit and constructor with a body |
| `statement(stmt, where)` | Every statement |
| `expression(expr, where)` | Every expression |
| `call(expr, callee, where)` | Every call; `callee` is a name such as `persistentHash` or `balances.insert` |

`where` tells you `circuit` (its name), `exported`, and `inAssert` (true inside the condition of an `assert`).

Custom rules see the syntax tree only. The data-flow facts used by the built-in rules (where a value comes from, how much entropy it has) are not exposed yet.
