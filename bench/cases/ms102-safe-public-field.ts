// expect: none
// note: public keys read from an object of secret keys are public

export function show(keys: { coinPublicKey: string; encryptionPublicKey: string }, shieldedSecretKeys: any) {
  const coinPublicKey = String(shieldedSecretKeys.coinPublicKey);
  console.log(`coin key: ${coinPublicKey}`);
  logger.info(`pays to ${shieldedSecretKeys.coinPublicKey.slice(0, 16)}..`);
}
