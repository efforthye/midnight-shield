// expect: none
// note: a step id, a translated label and a mask are not passwords

const steps = { password: "intro", next: "wallet" };
const korean = { password: "월렛 만들기" };
export function mask(parsed: { password?: string }) { parsed.password = '****'; return parsed; }
