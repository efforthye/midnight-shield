// A deliberately vulnerable DApp file: triggers the TypeScript/SDK rules.

declare const httpClientProofProvider: (url: string) => unknown;

// MS101: the proof server sees every user's private inputs. This one is remote.
export const proofProvider = httpClientProofProvider("https://proofs.example.com:6300");

// MS102: the wallet seed ends up in logs.
export function debugWallet(seed: string): void {
  console.log(`restoring wallet from ${seed}`);
}

// MS103: a real-looking wallet seed written into the code. Anyone who reads the repo can use it.
export const walletConfig = {
  seed: "9f3c2a7e5b1d4c8f6a0e2b9d7c5f1a3e8b6d4f2a0c9e7b5d3f1a8c6e4b2d0f97",
};

// MS104: the contract's private state saved where any script on the page can read it.
export function savePrivateState(privateState: unknown): void {
  localStorage.setItem("voting-private-state", JSON.stringify(privateState));
}

// MS105: Math.random() is predictable, so this commitment randomness can be guessed.
export function newBidRandomness(): string {
  return Math.random().toString(16).slice(2);
}

// MS106: the seed is sent to a server, which can read and log it.
export async function backupWallet(seed: string): Promise<void> {
  await fetch(`https://backup.example.com/save?seed=${seed}`);
}

// MS107: certificate checks are off, so anyone on the network can impersonate the backend.
export const agent = new https.Agent({ rejectUnauthorized: false });

// MS108: runs text received from outside as code.
export function runPlugin(script: string) {
  return eval(script);
}

// MS109: the indexer is reached over plain http, so answers can be read and changed.
export const config = { indexerUri: "http://indexer.example.com/api/v1/graphql" };

// MS110: the seed ends up in logs and error trackers.
export function checkSeed(seed: string) {
  if (seed.length !== 64) throw new Error(`invalid seed ${seed}`);
}

// MS111: the seed is written to disk as plain text.
export function saveWallet(seed: string) {
  writeFileSync("wallet.json", seed);
}

// MS112: any page in the parent window receives the state.
export function shareState(state: unknown) {
  window.parent.postMessage(state, "*");
}

// MS113: a fresh Uint8Array is all zeros, so this "randomness" is the same for everyone.
export const witnesses = {
  bidRandomness: ({ privateState }: { privateState: unknown }) => [privateState, new Uint8Array(32)],
};

// MS114: the seed ends up in browser history and server logs.
export function shareRestoreLink(seed: string) {
  history.pushState({}, "", `/restore?seed=${seed}`);
}

// MS115: every user's private state is locked with the same public password.
export const privateStateConfig = { privateStoragePasswordProvider: () => "Midnight-Wallet-2026!" };

// MS117: the seed is sent to an error tracker.
export function reportWalletError(seed: string) {
  Sentry.setContext("wallet", { seed });
}

// MS118: HTML from chain data is written into the page.
export function showMessage(el: HTMLElement, message: string) {
  el.innerHTML = message;
}

// MS119: VITE_ variables are copied into the browser bundle.
export const walletSeed = import.meta.env.VITE_WALLET_SEED;
