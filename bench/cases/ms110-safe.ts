// expect: none

export function f(secretKey: string) { throw new Error(`bad key of length ${secretKey.length}`); }
