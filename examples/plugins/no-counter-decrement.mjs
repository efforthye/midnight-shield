// Example custom rule for Midnight Shield.
// Use it with:  midnight-shield contracts/ --plugin examples/plugins/no-counter-decrement.mjs
// or list it under "plugins" in midnight-shield.config.json.

/** @type {import("midnight-shield").CustomRule[]} */
export default [
  {
    id: "ACME001",
    name: "no-counter-decrement",
    severity: "low",
    confidence: "high",
    summary: "Our contracts only ever count up; a decrement is probably a mistake.",
    docUrl: "https://example.com/rules/ACME001",
    check(ctx) {
      ctx.visit({
        call(expr, callee, where) {
          if (callee.endsWith(".decrement")) {
            ctx.report({ loc: expr.loc, message: `'${callee}' decrements a counter in circuit '${where.circuit}'.` });
          }
        },
      });
    },
  },
];
