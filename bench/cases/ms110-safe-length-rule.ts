// expect: none
// note: the error names the rule, not the passphrase

const MIN_PASSPHRASE_LENGTH = 12;
export function check(passphrase: string) {
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
}
