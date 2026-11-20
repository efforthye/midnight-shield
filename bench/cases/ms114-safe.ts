// expect: none

export function f(address: string) { history.pushState({}, "", `/account/${address}`); }
