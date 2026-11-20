// expect: MS110

export function f(secretKey: string) { throw new Error(`bad key ${secretKey}`); }
