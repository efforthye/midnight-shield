// expect: MS102
// note: a short prefix: reported as low, not as a leaked seed

export function built(seeds: { masterSeed: string }) {
  logger.info(`master seed: ${seeds.masterSeed.slice(0, 8)}...`);
}
