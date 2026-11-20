// expect: none
// note: secret derived from a wallet signature plus the address

export async function f(signature: string, address: string) { const sk = await hkdf(signature, address); return sk; }
