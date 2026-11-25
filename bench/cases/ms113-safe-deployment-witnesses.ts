// expect: none
// note: stand-ins the constructor needs; no circuit runs with them

export const deploymentWitnesses = {
  bidRandomness: (context: any) => [context.privateState, new Uint8Array(32)],
  salt: (context: any) => [context.privateState, new Uint8Array(32)],
};
