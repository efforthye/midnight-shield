// A deliberately vulnerable DApp file: triggers the TypeScript/SDK rules.

declare const httpClientProofProvider: (url: string) => unknown;

// MS101: the proof server sees every user's private inputs. This one is remote.
export const proofProvider = httpClientProofProvider("https://proofs.example.com:6300");

// MS102: the wallet seed ends up in logs.
export function debugWallet(seed: string): void {
  console.log(`restoring wallet from ${seed}`);
}
