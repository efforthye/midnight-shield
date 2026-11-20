// expect: MS106

export function f(ws: WebSocket, seed: string) { ws.send(seed); }
