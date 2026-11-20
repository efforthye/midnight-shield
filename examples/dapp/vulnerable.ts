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
