// expect: none

export async function f(seed: string) { await fetch("https://x.example.com", { method: "POST", body: JSON.stringify({ pk: publicKeyOf(seed) }) }); }
