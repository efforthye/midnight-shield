// expect: MS120

export async function f(walletAddress: string) { const voterSecret = await sha256(walletAddress); return voterSecret; }
