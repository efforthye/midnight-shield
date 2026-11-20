// expect: MS105
// note: randomness assigned to a neutral name first (expected miss)

const r = Math.random();
export const nonce = r.toString(36);
