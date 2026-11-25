// expect: none
// note: logs whether the variable is set, not its value

export function where() {
  console.log(`Using the fee wallet from ${process.env.FEE_WALLET_SEED ? 'FEE_WALLET_SEED' : 'wallet.json'}.`);
}
