// expect: none

export function f(address: string) { posthog.capture("connected", { address }); }
