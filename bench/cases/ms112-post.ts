// expect: MS112

export function f(d: unknown) { window.opener.postMessage(d, "*"); }
