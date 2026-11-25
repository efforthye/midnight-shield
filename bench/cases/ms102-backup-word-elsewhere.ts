// expect: MS102
// note: the word backup is a storage key, not a message to the user: the seed is logged

export function save(seed: string) {
  localStorage.setItem("backup-enabled", "yes");
  console.log(`seed: ${seed}`);
}
