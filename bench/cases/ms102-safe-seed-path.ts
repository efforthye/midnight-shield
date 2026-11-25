// expect: none
// note: where the seed is kept, not the seed

const SEED_PATH = "./wallet/seed.json";
export function where(seedPath: string) {
  console.log(`seed source: ${SEED_PATH} (not printed)`);
  console.error('keys derived', { seedPath });
}
