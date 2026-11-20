// VS Code extension: runs Midnight Shield on open, edited and saved files and
// shows findings as diagnostics (squiggles, Problems panel, hover with a link
// to the rule documentation).

import * as path from "node:path";
import * as vscode from "vscode";
import { loadConfig, type Config } from "../../src/config.js";
import { lintSource, mapDisclosures, type Finding } from "../../src/linter.js";
import { fileImportResolver } from "../../src/node.js";
import { isSdkFile, isTestFile } from "../../src/sdk.js";

const SEVERITY: Record<Finding["severity"], vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};

function settings() {
  const c = vscode.workspace.getConfiguration("midnightShield");
  return {
    enable: c.get<boolean>("enable", true),
    minSeverity: c.get<Finding["severity"]>("minSeverity", "info"),
    minConfidence: c.get<Finding["confidence"]>("minConfidence", "low"),
    checkTypeScript: c.get<boolean>("checkTypeScript", true),
  };
}

function projectConfig(doc: vscode.TextDocument): Config {
  const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
  if (!folder) return {};
  try {
    return loadConfig(undefined, folder.uri.fsPath) ?? {};
  } catch {
    return {};
  }
}

function shouldCheck(doc: vscode.TextDocument): boolean {
  if (doc.uri.scheme !== "file" && doc.uri.scheme !== "untitled") return false;
  const name = doc.fileName;
  if (name.endsWith(".compact") || doc.languageId === "compact") return true;
  return settings().checkTypeScript && isSdkFile(name) && !isTestFile(name);
}

export function toDiagnostic(f: Finding, doc: vscode.TextDocument): vscode.Diagnostic {
  const line = Math.max(0, Math.min(doc.lineCount - 1, f.line - 1));
  const text = doc.lineAt(line).text;
  const start = Math.max(0, f.col - 1);
  const word = text.slice(start).match(/^[A-Za-z_$][\w$]*(\(\))?/);
  const end = word ? start + word[0].length : text.length;
  const d = new vscode.Diagnostic(new vscode.Range(line, start, line, Math.max(end, start + 1)), f.message, SEVERITY[f.severity]);
  d.source = "Midnight Shield";
  d.code = { value: `${f.ruleId} ${f.ruleName}`, target: vscode.Uri.parse(f.docUrl) };
  return d;
}

export function activate(context: vscode.ExtensionContext): void {
  const collection = vscode.languages.createDiagnosticCollection("midnight-shield");
  const resolver = fileImportResolver();
  const timers = new Map<string, NodeJS.Timeout>();

  const check = (doc: vscode.TextDocument) => {
    const s = settings();
    if (!s.enable || !shouldCheck(doc)) return collection.delete(doc.uri);
    const config = projectConfig(doc);
    const folder = vscode.workspace.getWorkspaceFolder(doc.uri)?.uri.fsPath;
    const file = folder ? path.relative(folder, doc.fileName) : path.basename(doc.fileName);
    try {
      const findings = lintSource(doc.getText(), file, {
        resolver,
        absolutePath: doc.uri.scheme === "file" ? doc.fileName : undefined,
        disable: config.disable,
        minSeverity: s.minSeverity,
        minConfidence: s.minConfidence,
      });
      collection.set(doc.uri, findings.map((f) => toDiagnostic(f, doc)));
    } catch (e) {
      collection.delete(doc.uri);
      console.error("[midnight-shield]", e);
    }
  };

  const schedule = (doc: vscode.TextDocument) => {
    const key = doc.uri.toString();
    clearTimeout(timers.get(key));
    timers.set(key, setTimeout(() => check(doc), 300));
  };

  context.subscriptions.push(
    collection,
    vscode.workspace.onDidOpenTextDocument(check),
    vscode.workspace.onDidSaveTextDocument(check),
    vscode.workspace.onDidChangeTextDocument((e) => schedule(e.document)),
    vscode.workspace.onDidCloseTextDocument((doc) => collection.delete(doc.uri)),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("midnightShield")) vscode.workspace.textDocuments.forEach(check);
    }),
    vscode.commands.registerCommand("midnightShield.scanWorkspace", async () => {
      const files = await vscode.workspace.findFiles("**/*.compact", "**/{node_modules,dist,build,managed}/**");
      for (const uri of files) check(await vscode.workspace.openTextDocument(uri));
      vscode.commands.executeCommand("workbench.actions.view.problems");
      vscode.window.showInformationMessage(`Midnight Shield scanned ${files.length} Compact file(s).`);
    }),
    vscode.commands.registerCommand("midnightShield.showDisclosures", async () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (!doc || !doc.fileName.endsWith(".compact")) {
        vscode.window.showWarningMessage("Open a .compact file first.");
        return;
      }
      const entries = mapDisclosures(doc.getText(), path.basename(doc.fileName), { resolver, absolutePath: doc.fileName }).filter((d) => d.protection !== "constant");
      const lines = [
        `# Disclosure map: ${path.basename(doc.fileName)}`,
        "",
        "| Line | Circuit | Becomes public via | Private inputs | Protection | Findings |",
        "| --- | --- | --- | --- | --- | --- |",
        ...entries.map(
          (d) =>
            `| ${d.loc.line} | ${d.circuit} | ${d.via === "ledger write" ? `ledger ${d.target ?? ""}` : d.via} | ${d.sources.join(", ") || "-"} | ${d.protection}${d.secretBits !== undefined ? ` (${d.secretBits} bits)` : ""} | ${d.findings.join(", ")} |`,
        ),
      ];
      const md = await vscode.workspace.openTextDocument({ language: "markdown", content: lines.join("\n") });
      await vscode.commands.executeCommand("markdown.showPreview", md.uri);
    }),
  );

  vscode.workspace.textDocuments.forEach(check);
}

export function deactivate(): void {}
