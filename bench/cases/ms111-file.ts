// expect: MS111

export function f(seed: string) { fs.writeFileSync("seed.txt", seed); }
