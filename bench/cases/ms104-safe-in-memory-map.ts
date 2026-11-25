// expect: none
// note: kept in memory for the session, not in the browser

const signingKeyStore = new Map<string, unknown>();
export async function setSigningKey(address: string, signingKey: unknown) { signingKeyStore.set(address, signingKey); }
