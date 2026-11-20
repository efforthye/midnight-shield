# Midnight Shield for VS Code

Security and privacy diagnostics for [Midnight](https://midnight.network) Compact contracts, as you type.

- Squiggles and Problems-panel entries for all Midnight Shield rules (MS001 to MS010 for Compact, MS101 and MS102 for TypeScript/JavaScript).
- Hover a finding and click the rule ID to open its documentation.
- Follows `import "..."` into other files.
- Respects `midnight-shield.config.json` in the workspace (`disable`), and inline `// shield-disable-next-line` comments.
- Commands: **Midnight Shield: Scan workspace** and **Midnight Shield: Show disclosure map for this file**.

Everything runs locally. Your code is never sent anywhere.

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `midnightShield.enable` | `true` | Show diagnostics |
| `midnightShield.minSeverity` | `info` | Hide findings below this severity |
| `midnightShield.minConfidence` | `low` | Hide findings below this confidence |
| `midnightShield.checkTypeScript` | `true` | Also check TypeScript/JavaScript files |

## Build from source

```bash
cd vscode
npm install
npm run package   # creates midnight-shield-vscode-<version>.vsix
code --install-extension midnight-shield-vscode-*.vsix
```

This extension is a community project, not an official Midnight Foundation product.
