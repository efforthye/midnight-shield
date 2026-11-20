// expect: none

export function f() { const voterSecret = crypto.getRandomValues(new Uint8Array(32)); return voterSecret; }
