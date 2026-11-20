// expect: MS113

export const witnesses = {
  salt: ({ privateState }) => [privateState, BigInt(Date.now())],
};
