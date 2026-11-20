// The same DApp code written safely. Midnight Shield reports nothing here.

declare const httpClientProofProvider: (url: string) => unknown;
declare const publicKeyOf: (seed: string) => string;

// The proof server runs on the user's own machine.
export const proofProvider = httpClientProofProvider(process.env.MIDNIGHT_PROOF_SERVER ?? "http://localhost:6300");

// Log a derived, public value instead of the seed.
export function debugWallet(seed: string): void {
  console.log(`restoring wallet for ${publicKeyOf(seed)} (seed length ${seed.length})`);
}
