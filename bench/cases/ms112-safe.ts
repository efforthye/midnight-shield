// expect: none

export function f(d: unknown) { window.opener.postMessage(d, location.origin); }
