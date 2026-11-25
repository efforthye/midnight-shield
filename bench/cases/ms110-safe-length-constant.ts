// expect: none
// note: the size of a secret, not the secret

const SECRET_BYTES = 32;
export function check(value: Uint8Array, name: string) {
  if (value.length !== SECRET_BYTES) throw new Error(`${name} must be exactly ${SECRET_BYTES} bytes`);
}
