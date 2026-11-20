// expect: none
// note: Math.random() only in a fallback branch of a reassigned variable

export async function f() {
  let pubKey = await getAddress();
  if (!pubKey) pubKey = "MOCK" + Math.random().toString(36);
  const label = await show(pubKey);
  return label;
}
