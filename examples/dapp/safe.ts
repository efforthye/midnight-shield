// The same DApp code written safely. Midnight Shield reports nothing here.

declare const httpClientProofProvider: (url: string) => unknown;
declare const publicKeyOf: (seed: string) => string;

// The proof server runs on the user's own machine.
export const proofProvider = httpClientProofProvider(process.env.MIDNIGHT_PROOF_SERVER ?? "http://localhost:6300");

// Log a derived, public value instead of the seed.
export function debugWallet(seed: string): void {
  console.log(`restoring wallet for ${publicKeyOf(seed)} (seed length ${seed.length})`);
}

// The seed comes from the environment (or the user's wallet), never from the source.
export const walletConfig = {
  seed: process.env.WALLET_SEED ?? "",
};

// Only a non-sensitive preference goes to browser storage.
export function saveTheme(theme: string): void {
  localStorage.setItem("theme", theme);
}

// Commitment randomness from a cryptographically secure source.
export function newBidRandomness(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

// Only a public value leaves the device.
export async function registerWallet(seed: string): Promise<void> {
  await fetch("https://api.example.com/register", { method: "POST", body: JSON.stringify({ publicKey: publicKeyOf(seed) }) });
}

export const witnesses = {
  bidRandomness: ({ privateState }: { privateState: unknown }) => [privateState, crypto.getRandomValues(new Uint8Array(32))],
};

export function showMessage(el: HTMLElement, message: string) {
  el.textContent = message;
}

export const indexerUrl = import.meta.env.VITE_INDEXER_URL;

export function newVoterSecret() {
  const voterSecret = crypto.getRandomValues(new Uint8Array(32));
  return voterSecret;
}
