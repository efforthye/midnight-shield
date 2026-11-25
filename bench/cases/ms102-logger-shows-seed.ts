// expect: MS102
// note: shown to the user on purpose, but the logger also writes it to files: medium

export function built(logger: any, seeds: { masterSeed: string }) {
  logger.info(`Your wallet seed is: ${seeds.masterSeed}`);
}
