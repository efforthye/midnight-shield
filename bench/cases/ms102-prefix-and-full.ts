// expect: MS102
// note: the whole seed is logged too: high

export function built(seeds: { masterSeed: string }) {
  logger.info(`seed ${seeds.masterSeed.slice(0, 8)} is ${seeds.masterSeed}`);
}
