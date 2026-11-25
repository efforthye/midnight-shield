// expect: none
// note: Math.random() shuffles an order; the secrets come from elsewhere

export function pick(approverSecrets: string[], n: number) {
  const picks = [...approverSecrets].sort(() => Math.random() - 0.5).slice(0, n);
  return picks;
}
