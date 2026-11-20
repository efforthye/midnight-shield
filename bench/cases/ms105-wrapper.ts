// expect: MS105

const r = () => Math.random();
export const nonce = r().toString(36);
