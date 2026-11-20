// expect: none

export const witnesses = {
  bidRandomness: ({ privateState }) => [privateState, crypto.getRandomValues(new Uint8Array(32))],
  secretKey: ({ privateState }) => [privateState, privateState.secretKey],
};
