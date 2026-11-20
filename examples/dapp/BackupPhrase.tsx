// MS116: the recovery phrase is always on screen, where screenshots and session replay can capture it.
export function BackupPhrase({ mnemonic }: { mnemonic: string }) {
  return <p className="phrase">{mnemonic}</p>;
}
