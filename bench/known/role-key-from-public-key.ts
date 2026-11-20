// expect: MS120
// source: pending (public project; linked here once the maintainers have been told)
// note: minimal reproduction. Every role's key is derived from the public coin key and a salt in the source.
export async function claimPage(addresses: { shieldedCoinPublicKey: string }) {
  const investorSk = await deriveRoleKey(addresses.shieldedCoinPublicKey, "investor");
  return investorSk;
}
