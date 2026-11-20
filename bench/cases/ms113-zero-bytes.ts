// expect: MS113

export const witnesses = {
  bidRandomness: ({ privateState }) => [privateState, new Uint8Array(32)],
};
