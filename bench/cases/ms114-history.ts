// expect: MS114

export function f(seed: string) { history.pushState({}, "", `/restore?seed=${seed}`); }
