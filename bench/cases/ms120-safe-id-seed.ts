// expect: none
// note: a seed for an identifier, not a secret

export function contractId(propertyAddress: string, tenantWallet: string) {
  const contractIdSeed = JSON.stringify({ propertyAddress, tenantWallet });
  return contractIdSeed;
}
