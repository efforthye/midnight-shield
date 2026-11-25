// expect: none
// note: Midnight's private state provider is the right place for private state

export async function save(providers: any, id: string, privateState: unknown) {
  const store = providers.privateStateProvider;
  await store.set(id, privateState);
}
