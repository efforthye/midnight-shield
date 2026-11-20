// expect: none

export function f(seed: string) { fs.writeFileSync("seed.txt", seed, { mode: 0o600 }); }
