// expect: none
// note: derived by a service the analyzer cannot see into

export async function load(v2q: any, contractAddress: string) {
  const qualificationSecret = await v2q.service.qualificationSecret(contractAddress);
  return qualificationSecret;
}
