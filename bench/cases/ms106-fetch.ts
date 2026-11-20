// expect: MS106

export async function f(seed: string) { await fetch(`https://x.example.com/?s=${seed}`); }
