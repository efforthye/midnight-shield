// expect: MS117

export function f(seed: string) { Sentry.setContext("wallet", { seed }); }
