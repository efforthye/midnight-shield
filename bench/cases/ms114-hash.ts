// expect: MS114

export function f(mnemonic: string) { location.hash = `#${mnemonic}`; }
