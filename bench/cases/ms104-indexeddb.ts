// expect: MS104

export async function f(store: IDBObjectStore, privateState: unknown) { await store.put(privateState, "ps"); }
