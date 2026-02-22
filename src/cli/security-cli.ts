import fs from "node:fs/promises";
import type { Command } from "commander";
import { loadConfig } from "../config/config.js";
import type { TrustConfig } from "../config/types.trust.js";
import { defaultRuntime } from "../runtime.js";
import { runSecurityAudit } from "../security/audit.js";
import { fixSecurityFootguns } from "../security/fix.js";
import { formatDocsLink } from "../terminal/links.js";
import { isRich, theme } from "../terminal/theme.js";
import {
  exportTrustAuditEventsToSiem,
  simulateTrustPolicyAgainstAudit,
  type TrustSiemExportFormat,
} from "../trust/compliance.js";
import { shortenHomeInString, shortenHomePath } from "../utils.js";
import { formatCliCommand } from "./command-format.js";
import { formatHelpExamples } from "./help-format.js";

type SecurityAuditOptions = {
  json?: boolean;
  deep?: boolean;
  fix?: boolean;
};

type SecurityTrustExportOptions = {
  out?: string;
  format?: string;
  auditPath?: string;
  limit?: string;
  verifyChain?: boolean;
  includePayload?: boolean;
  json?: boolean;
};

type SecurityTrustSimulationOptions = {
  policyFile: string;
  auditPath?: string;
  limit?: string;
  json?: boolean;
};

function formatSummary(summary: { critical: number; warn: number; info: number }): string {
  const rich = isRich();
  const c = summary.critical;
  const w = summary.warn;
  const i = summary.info;
  const parts: string[] = [];
  parts.push(rich ? theme.error(`${c} critical`) : `${c} critical`);
  parts.push(rich ? theme.warn(`${w} warn`) : `${w} warn`);
  parts.push(rich ? theme.muted(`${i} info`) : `${i} info`);
  return parts.join(" · ");
}

function parsePositiveIntOption(raw: string | undefined, name: string): number | undefined {
  if (!raw || raw.trim().length === 0) {
    return undefined;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function parseTrustExportFormat(raw: string | undefined): TrustSiemExportFormat {
  if (!raw || raw.trim().length === 0) {
    return "jsonl";
  }
  const normalized = raw.trim().toLowerCase();
  if (normalized === "jsonl" || normalized === "json") {
    return normalized;
  }
  throw new Error(`unsupported format: ${raw} (use jsonl or json)`);
}

function parseTrustPolicyPatch(raw: string): Partial<TrustConfig> {
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("policy file must contain a JSON object");
  }
  return parsed as Partial<TrustConfig>;
}

export function registerSecurityCli(program: Command) {
  const security = program
    .command("security")
    .description("Audit local config and state for common security foot-guns")
    .addHelpText(
      "after",
      () =>
        `\n${theme.heading("Examples:")}\n${formatHelpExamples([
          ["openclaw security audit", "Run a local security audit."],
          ["openclaw security audit --deep", "Include best-effort live Gateway probe checks."],
          ["openclaw security audit --fix", "Apply safe remediations and file-permission fixes."],
          ["openclaw security audit --json", "Output machine-readable JSON."],
          [
            "openclaw security trust export --out trust-siem.jsonl",
            "Export trust audit SIEM records.",
          ],
          [
            "openclaw security trust simulate --policy-file policy.json --json",
            "Preview policy blast radius against recorded trust events.",
          ],
        ])}\n\n${theme.muted("Docs:")} ${formatDocsLink("/cli/security", "docs.openclaw.ai/cli/security")}\n`,
    );

  const trust = security
    .command("trust")
    .description("Trust audit evidence export and policy simulation");

  trust
    .command("export")
    .description("Export trust audit chain to SIEM-friendly records")
    .option("--out <path>", "Write export to a file instead of stdout")
    .option("--format <format>", "Export format: jsonl or json", "jsonl")
    .option("--audit-path <path>", "Optional trust audit JSONL path override")
    .option("--limit <n>", "Export only the most recent n events")
    .option("--verify-chain", "Verify immutable audit hash chain before export", false)
    .option("--include-payload", "Include outbound payload snippets in export", false)
    .option("--json", "Print command result as JSON", false)
    .action(async (opts: SecurityTrustExportOptions) => {
      const cfg = loadConfig();
      const limit = parsePositiveIntOption(opts.limit, "limit");
      const format = parseTrustExportFormat(opts.format);
      const exported = await exportTrustAuditEventsToSiem({
        cfg,
        auditPath: opts.auditPath?.trim() || undefined,
        outFile: opts.out?.trim() || undefined,
        format,
        limit,
        verifyChain: opts.verifyChain === true,
        includePayload: opts.includePayload === true,
      });

      if (opts.json) {
        defaultRuntime.log(
          JSON.stringify(
            {
              ok: true,
              format: exported.format,
              count: exported.records.length,
              outputPath: exported.outputPath ?? null,
              verification: exported.verification ?? null,
            },
            null,
            2,
          ),
        );
        return;
      }

      if (exported.outputPath) {
        const verification = exported.verification
          ? exported.verification.valid
            ? "valid"
            : `invalid (${exported.verification.error ?? "unknown"})`
          : "not requested";
        defaultRuntime.log(
          [
            `Trust SIEM export: ${exported.records.length} event(s) written to ${shortenHomePath(exported.outputPath)}`,
            `Format: ${exported.format}`,
            `Chain verification: ${verification}`,
          ].join("\n"),
        );
        return;
      }

      defaultRuntime.log(exported.serialized);
    });

  trust
    .command("simulate")
    .description("Replay trust audit events against a candidate policy patch")
    .requiredOption("--policy-file <path>", "JSON file containing a partial trust policy patch")
    .option("--audit-path <path>", "Optional trust audit JSONL path override")
    .option("--limit <n>", "Replay only the most recent n events")
    .option("--json", "Print simulation result as JSON", false)
    .action(async (opts: SecurityTrustSimulationOptions) => {
      const cfg = loadConfig();
      const limit = parsePositiveIntOption(opts.limit, "limit");
      const rawPolicy = await fs.readFile(opts.policyFile, "utf-8");
      const candidateTrustConfig = parseTrustPolicyPatch(rawPolicy);

      const simulation = await simulateTrustPolicyAgainstAudit({
        cfg,
        auditPath: opts.auditPath?.trim() || undefined,
        limit,
        candidateTrustConfig,
      });

      if (opts.json) {
        defaultRuntime.log(JSON.stringify(simulation, null, 2));
        return;
      }

      const lines: string[] = [
        "Trust policy simulation",
        `Replayable events: ${simulation.replayedEvents}/${simulation.totalEvents}`,
        `Changed decisions: ${simulation.changedEvents}`,
        `Blast radius: ${(simulation.changeRate * 100).toFixed(2)}%`,
        `Posture score (current -> candidate): ${simulation.posture.current.score} -> ${simulation.posture.candidate.score}`,
      ];
      if (simulation.posture.drift.length > 0) {
        lines.push(`Posture drift: ${simulation.posture.drift.join(", ")}`);
      }
      if (simulation.changes.length > 0) {
        lines.push("");
        lines.push("Sample changes:");
        for (const change of simulation.changes.slice(0, 10)) {
          lines.push(
            `- ${change.stage} ${change.operation}: ${change.from} -> ${change.to} (${change.reason})`,
          );
        }
      }
      defaultRuntime.log(lines.join("\n"));
    });

  security
    .command("audit")
    .description("Audit config + local state for common security foot-guns")
    .option("--deep", "Attempt live Gateway probe (best-effort)", false)
    .option("--fix", "Apply safe fixes (tighten defaults + chmod state/config)", false)
    .option("--json", "Print JSON", false)
    .action(async (opts: SecurityAuditOptions) => {
      const fixResult = opts.fix ? await fixSecurityFootguns().catch((_err) => null) : null;

      const cfg = loadConfig();
      const report = await runSecurityAudit({
        config: cfg,
        deep: Boolean(opts.deep),
        includeFilesystem: true,
        includeChannelSecurity: true,
      });

      if (opts.json) {
        defaultRuntime.log(
          JSON.stringify(fixResult ? { fix: fixResult, report } : report, null, 2),
        );
        return;
      }

      const rich = isRich();
      const heading = (text: string) => (rich ? theme.heading(text) : text);
      const muted = (text: string) => (rich ? theme.muted(text) : text);

      const lines: string[] = [];
      lines.push(heading("OpenClaw security audit"));
      lines.push(muted(`Summary: ${formatSummary(report.summary)}`));
      lines.push(muted(`Run deeper: ${formatCliCommand("openclaw security audit --deep")}`));

      if (opts.fix) {
        lines.push(muted(`Fix: ${formatCliCommand("openclaw security audit --fix")}`));
        if (!fixResult) {
          lines.push(muted("Fixes: failed to apply (unexpected error)"));
        } else if (
          fixResult.errors.length === 0 &&
          fixResult.changes.length === 0 &&
          fixResult.actions.every((a) => !a.ok)
        ) {
          lines.push(muted("Fixes: no changes applied"));
        } else {
          lines.push("");
          lines.push(heading("FIX"));
          for (const change of fixResult.changes) {
            lines.push(muted(`  ${shortenHomeInString(change)}`));
          }
          for (const action of fixResult.actions) {
            if (action.kind === "chmod") {
              const mode = action.mode.toString(8).padStart(3, "0");
              if (action.ok) {
                lines.push(muted(`  chmod ${mode} ${shortenHomePath(action.path)}`));
              } else if (action.skipped) {
                lines.push(
                  muted(`  skip chmod ${mode} ${shortenHomePath(action.path)} (${action.skipped})`),
                );
              } else if (action.error) {
                lines.push(
                  muted(`  chmod ${mode} ${shortenHomePath(action.path)} failed: ${action.error}`),
                );
              }
              continue;
            }
            const command = shortenHomeInString(action.command);
            if (action.ok) {
              lines.push(muted(`  ${command}`));
            } else if (action.skipped) {
              lines.push(muted(`  skip ${command} (${action.skipped})`));
            } else if (action.error) {
              lines.push(muted(`  ${command} failed: ${action.error}`));
            }
          }
          if (fixResult.errors.length > 0) {
            for (const err of fixResult.errors) {
              lines.push(muted(`  error: ${shortenHomeInString(err)}`));
            }
          }
        }
      }

      const bySeverity = (sev: "critical" | "warn" | "info") =>
        report.findings.filter((f) => f.severity === sev);

      const render = (sev: "critical" | "warn" | "info") => {
        const list = bySeverity(sev);
        if (list.length === 0) {
          return;
        }
        const label =
          sev === "critical"
            ? rich
              ? theme.error("CRITICAL")
              : "CRITICAL"
            : sev === "warn"
              ? rich
                ? theme.warn("WARN")
                : "WARN"
              : rich
                ? theme.muted("INFO")
                : "INFO";
        lines.push("");
        lines.push(heading(label));
        for (const f of list) {
          lines.push(`${theme.muted(f.checkId)} ${f.title}`);
          lines.push(`  ${f.detail}`);
          if (f.remediation?.trim()) {
            lines.push(`  ${muted(`Fix: ${f.remediation.trim()}`)}`);
          }
        }
      };

      render("critical");
      render("warn");
      render("info");

      defaultRuntime.log(lines.join("\n"));
    });
}
