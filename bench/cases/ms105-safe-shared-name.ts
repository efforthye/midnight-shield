// expect: none
// note: a parameter that shares a name with a Math.random() value elsewhere

export function simulate() { const temperature = 20 + Math.random() * 10; return temperature; }
export async function proof(temperature: number, deviceSecret: string) {
  const secretTag = deviceSecret;
  return { temperature, secretTag };
}
