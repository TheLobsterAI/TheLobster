import fs from "node:fs/promises";
import path from "node:path";
import type { OpenClawConfig } from "../config/config.js";
import type {
  TrustActorType,
  TrustConfig,
  TrustDataClassification,
  TrustDestinationKind,
  TrustRiskLevel,
} from "../config/types.trust.js";
import { readTrustAuditEvents, verifyTrustAuditLog } from "./audit-store.js";
import { buildSyntheticApprovalGrant, resolveTrustRuntimeConfig } from "./runtime.js";
import {
  calculateTrustPostureScore,
  detectTrustDrift,
  evaluateTrustPolicy,
  type TrustAction,
  type TrustAuditEvent,
  type TrustDecision,
  type TrustPostureSignals,
  type TrustStage,
} from "./trust-plane.js";

export type TrustSiemExportFormat = "jsonl" | "json";

export type TrustSiemExportResult = {
  records: Record<string, unknown>[];
  serialized: string;
  format: TrustSiemExportFormat;
  outputPath?: string;
  verification?: { valid: boolean; error?: string; index?: number };
};

export type TrustPostureSummary = {
  signals: TrustPostureSignals;
  score: number;
};

export type TrustSimulationChange = {
  eventId: string;
  actionId: string;
  stage: TrustStage;
  operation: string;
  from: TrustDecision;
  to: TrustDecision;
  reason: string;
};

export type TrustSimulationResult = {
  totalEvents: number;
  replayedEvents: number;
  skippedEvents: number;
  unchangedEvents: number;
  changedEvents: number;
  changeRate: number;
  changes: TrustSimulationChange[];
  posture: {
    current: TrustPostureSummary;
    candidate: TrustPostureSummary;
    drift: Array<keyof TrustPostureSignals>;
  };
};

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function normalizeString(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizeDataClass(value: unknown): TrustDataClassification | null {
  if (
    value === "public" ||
    value === "internal" ||
    value === "confidential" ||
    value === "restricted" ||
    value === "secret"
  ) {
    return value;
  }
  return null;
}

function normalizeRisk(value: unknown): TrustRiskLevel | null {
  if (value === "low" || value === "medium" || value === "high" || value === "critical") {
    return value;
  }
  if (value === "unknown") {
    return "unknown";
  }
  return null;
}

function normalizeDecision(value: unknown): TrustDecision | null {
  if (value === "allow" || value === "deny" || value === "step-up") {
    return value;
  }
  return null;
}

function normalizeStage(value: unknown): TrustStage | null {
  if (value === "proposal" || value === "execution" || value === "outbound") {
    return value;
  }
  return null;
}

function normalizeDestinationKind(value: unknown): TrustDestinationKind | null {
  if (
    value === "none" ||
    value === "chat" ||
    value === "http" ||
    value === "email" ||
    value === "file" ||
    value === "connector" ||
    value === "tool"
  ) {
    return value;
  }
  return null;
}

function normalizeActorType(value: unknown): TrustActorType | null {
  if (value === "human" || value === "agent" || value === "service") {
    return value;
  }
  return null;
}

function redactPayload(payload: Record<string, unknown>): Record<string, unknown> {
  const clone = { ...payload };
  delete clone.textPayload;
  delete clone.filePayloads;
  return clone;
}

function resolveSiemOutcome(params: {
  eventKind: TrustAuditEvent["kind"];
  payload: Record<string, unknown>;
}): "success" | "failure" | "unknown" {
  const decision = normalizeDecision(params.payload.decision);
  if (decision === "allow") {
    return "success";
  }
  if (decision === "deny") {
    return "failure";
  }
  if (params.eventKind === "approval") {
    const approvalDecision = normalizeString(params.payload.decision);
    if (approvalDecision?.startsWith("allow")) {
      return "success";
    }
    if (approvalDecision === "deny") {
      return "failure";
    }
  }
  return "unknown";
}

function resolveSiemAction(params: {
  eventKind: TrustAuditEvent["kind"];
  payload: Record<string, unknown>;
}) {
  const operation = normalizeString(params.payload.operation);
  if (operation) {
    return operation;
  }
  if (params.eventKind === "approval") {
    return "approval";
  }
  return params.eventKind;
}

export function mapTrustAuditEventToSiemRecord(params: {
  event: TrustAuditEvent;
  includePayload?: boolean;
}): Record<string, unknown> {
  const payload = asRecord(params.event.payload) ?? {};
  const payloadForExport = params.includePayload ? payload : redactPayload(payload);
  const outcome = resolveSiemOutcome({ eventKind: params.event.kind, payload });
  const source = asRecord(payload.source);
  const destination = asRecord(payload.destination);
  const context = asRecord(payload.context);

  return {
    "@timestamp": new Date(params.event.tsMs).toISOString(),
    event: {
      kind: params.event.kind,
      action: resolveSiemAction({ eventKind: params.event.kind, payload }),
      category: ["security", "iam"],
      type: [params.event.kind],
      outcome,
    },
    openclaw: {
      tenantId: params.event.tenantId,
      actorId: params.event.actorId,
      actionId: params.event.actionId,
      trust: {
        stage: normalizeStage(payload.stage),
        intent: normalizeString(payload.intent),
        operation: normalizeString(payload.operation),
        risk: normalizeRisk(payload.risk),
        decision: normalizeDecision(payload.decision) ?? normalizeString(payload.decision),
        reason: normalizeString(payload.reason),
        matchedRuleId: normalizeString(payload.matchedRuleId),
        mode: normalizeString(payload.mode),
        channel: normalizeString(context?.channel),
        audience: normalizeString(context?.audience),
      },
    },
    source:
      source && normalizeString(source.system)
        ? {
            service: {
              name: normalizeString(source.system),
            },
            resource: normalizeString(source.resource),
            dataClass: normalizeDataClass(source.dataClass),
          }
        : undefined,
    destination:
      destination && normalizeString(destination.target)
        ? {
            kind: normalizeDestinationKind(destination.kind),
            target: normalizeString(destination.target),
            dataClass: normalizeDataClass(destination.dataClass),
          }
        : undefined,
    integrity: {
      hash: params.event.hash,
      previousHash: params.event.previousHash,
    },
    payload: payloadForExport,
  };
}

function serializeRecords(
  records: Record<string, unknown>[],
  format: TrustSiemExportFormat,
): string {
  if (format === "json") {
    return `${JSON.stringify(records, null, 2)}\n`;
  }
  return `${records.map((record) => JSON.stringify(record)).join("\n")}\n`;
}

export async function exportTrustAuditEventsToSiem(params: {
  cfg?: OpenClawConfig;
  auditPath?: string;
  outFile?: string;
  format?: TrustSiemExportFormat;
  limit?: number;
  verifyChain?: boolean;
  includePayload?: boolean;
}): Promise<TrustSiemExportResult> {
  const format = params.format ?? "jsonl";
  const events = await readTrustAuditEvents({
    cfg: params.cfg,
    overridePath: params.auditPath,
    limit: params.limit,
  });
  const records = events.map((event) =>
    mapTrustAuditEventToSiemRecord({
      event,
      includePayload: params.includePayload === true,
    }),
  );
  const serialized = serializeRecords(records, format);
  let outputPath: string | undefined;
  if (params.outFile) {
    outputPath = path.resolve(params.outFile);
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await fs.writeFile(outputPath, serialized, "utf8");
  }

  const verification = params.verifyChain
    ? await verifyTrustAuditLog({ cfg: params.cfg, overridePath: params.auditPath })
    : undefined;

  return { records, serialized, format, outputPath, verification };
}

export function mergeTrustConfig(
  base: TrustConfig | undefined,
  patch: Partial<TrustConfig>,
): TrustConfig {
  return {
    ...base,
    ...patch,
    layers: patch.layers ? { ...base?.layers, ...patch.layers } : base?.layers,
    audit: patch.audit ? { ...base?.audit, ...patch.audit } : base?.audit,
    emergency: patch.emergency ? { ...base?.emergency, ...patch.emergency } : base?.emergency,
    riskHints: patch.riskHints
      ? {
          ...base?.riskHints,
          ...patch.riskHints,
          exec: patch.riskHints.exec
            ? { ...base?.riskHints?.exec, ...patch.riskHints.exec }
            : base?.riskHints?.exec,
          message: patch.riskHints.message
            ? { ...base?.riskHints?.message, ...patch.riskHints.message }
            : base?.riskHints?.message,
        }
      : base?.riskHints,
  };
}

function deriveTrustPostureSignals(params: {
  runtime: ReturnType<typeof resolveTrustRuntimeConfig>;
}): TrustPostureSignals {
  const hasDualControlRule = Object.values(params.runtime.policy.layers).some((rules) =>
    (rules ?? []).some((rule) => rule.dualControl === true),
  );
  return {
    denyByDefault: params.runtime.policy.unknownRiskDecision === "deny",
    stagedChecks: params.runtime.enabled,
    contextBoundApprovals: true,
    outboundAllowlist: (params.runtime.policy.outboundDestinationAllowlist ?? []).length > 0,
    outboundDlp: true,
    immutableAuditChain: params.runtime.auditEnabled,
    dualControl: hasDualControlRule,
  };
}

function stageFromEventKind(kind: TrustAuditEvent["kind"]): TrustStage {
  if (kind === "execution") {
    return "execution";
  }
  if (kind === "delivery") {
    return "outbound";
  }
  return "proposal";
}

function rebuildActionFromAuditEvent(params: {
  event: TrustAuditEvent;
  policyVersion: string;
}): TrustAction | null {
  const payload = asRecord(params.event.payload);
  if (!payload) {
    return null;
  }
  const source = asRecord(payload.source);
  const destination = asRecord(payload.destination);
  const context = asRecord(payload.context);
  const actor = asRecord(payload.actor);

  const operation = normalizeString(payload.operation) ?? "unknown";
  const intent = normalizeString(payload.intent) ?? `replay:${operation}`;
  const stage = normalizeStage(payload.stage) ?? stageFromEventKind(params.event.kind);
  const risk = normalizeRisk(payload.risk) ?? "unknown";

  const sourceDataClass = normalizeDataClass(source?.dataClass) ?? "internal";
  const destinationDataClass = normalizeDataClass(destination?.dataClass) ?? sourceDataClass;

  const destinationKind = normalizeDestinationKind(destination?.kind) ?? "tool";
  const destinationTarget = normalizeString(destination?.target) ?? "unknown";

  const channel = normalizeString(context?.channel) ?? "audit-replay";
  const audience = normalizeString(context?.audience) ?? "audit";
  const sessionId = normalizeString(context?.sessionId) ?? `replay-${params.event.actionId}`;
  const policyVersion = normalizeString(context?.policyVersion) ?? params.policyVersion;
  const occurredAtMs =
    typeof context?.occurredAtMs === "number" ? context.occurredAtMs : params.event.tsMs;
  const membershipVersion = normalizeString(context?.membershipVersion) ?? undefined;

  const actorType = normalizeActorType(actor?.actorType) ?? "service";
  const roleVersion = normalizeString(actor?.roleVersion) ?? undefined;
  const roles = Array.isArray(actor?.roles)
    ? actor.roles.filter((value): value is string => typeof value === "string")
    : undefined;

  const textPayload = normalizeString(payload.textPayload) ?? undefined;
  const filePayloads = Array.isArray(payload.filePayloads)
    ? payload.filePayloads.filter(
        (value): value is string => typeof value === "string" && value.trim().length > 0,
      )
    : undefined;

  return {
    id: `replay-${params.event.id}`,
    intent,
    operation,
    actor: {
      tenantId: params.event.tenantId,
      actorId: params.event.actorId,
      actorType,
      roleVersion,
      roles,
    },
    source: {
      system: normalizeString(source?.system) ?? "audit",
      resource: normalizeString(source?.resource) ?? "audit-log",
      dataClass: sourceDataClass,
      tenantId: params.event.tenantId,
    },
    destination: {
      kind: destinationKind,
      target: destinationTarget,
      dataClass: destinationDataClass,
      destinationVersion: normalizeString(destination?.destinationVersion) ?? policyVersion,
    },
    context: {
      channel,
      audience,
      sessionId,
      occurredAtMs,
      membershipVersion,
      policyVersion,
    },
    risk,
    stage,
    textPayload,
    filePayloads,
  };
}

function buildReplayApprovals(params: { action: TrustAction; payload: Record<string, unknown> }) {
  const approval = asRecord(params.payload.approval);
  if (!approval || approval.satisfied !== true) {
    return undefined;
  }
  const grantId = normalizeString(approval.grantId) ?? `replay-${params.action.id}`;
  const dualControlRequired = approval.dualControlRequired === true;
  return [
    buildSyntheticApprovalGrant({
      action: params.action,
      approvalId: grantId,
      approvers: dualControlRequired ? ["audit-replay-a", "audit-replay-b"] : ["audit-replay-a"],
      scope: "once",
      ttlMs: 300_000,
    }),
  ];
}

export async function simulateTrustPolicyAgainstAudit(params: {
  cfg?: OpenClawConfig;
  auditPath?: string;
  limit?: number;
  candidateTrustConfig: Partial<TrustConfig>;
}): Promise<TrustSimulationResult> {
  const baseTrust = params.cfg?.trust;
  const candidateTrust = mergeTrustConfig(baseTrust, params.candidateTrustConfig);
  const currentRuntime = resolveTrustRuntimeConfig({ cfg: params.cfg, trustConfig: baseTrust });
  const candidateRuntime = resolveTrustRuntimeConfig({
    cfg: params.cfg,
    trustConfig: candidateTrust,
  });

  const currentSignals = deriveTrustPostureSignals({ runtime: currentRuntime });
  const candidateSignals = deriveTrustPostureSignals({ runtime: candidateRuntime });

  const events = await readTrustAuditEvents({
    cfg: params.cfg,
    overridePath: params.auditPath,
    limit: params.limit,
  });

  let replayedEvents = 0;
  let skippedEvents = 0;
  let changedEvents = 0;
  let unchangedEvents = 0;
  const changes: TrustSimulationChange[] = [];

  for (const event of events) {
    if (event.kind === "approval") {
      skippedEvents += 1;
      continue;
    }

    const action = rebuildActionFromAuditEvent({
      event,
      policyVersion: currentRuntime.policy.version,
    });
    if (!action) {
      skippedEvents += 1;
      continue;
    }

    replayedEvents += 1;
    const payload = asRecord(event.payload) ?? {};
    const baselineApprovals = buildReplayApprovals({ action, payload });
    const baselineDecision = normalizeDecision(payload.decision)
      ? (payload.decision as TrustDecision)
      : evaluateTrustPolicy({
          action,
          policy: currentRuntime.policy,
          approvals: baselineApprovals,
        }).decision;

    const candidateAction: TrustAction = {
      ...action,
      context: {
        ...action.context,
        policyVersion: candidateRuntime.policy.version,
      },
    };
    const candidateApprovals = buildReplayApprovals({
      action: candidateAction,
      payload,
    });
    const candidateEvaluation = evaluateTrustPolicy({
      action: candidateAction,
      policy: candidateRuntime.policy,
      approvals: candidateApprovals,
    });

    if (candidateEvaluation.decision !== baselineDecision) {
      changedEvents += 1;
      if (changes.length < 50) {
        changes.push({
          eventId: event.id,
          actionId: event.actionId,
          stage: candidateAction.stage,
          operation: candidateAction.operation,
          from: baselineDecision,
          to: candidateEvaluation.decision,
          reason: candidateEvaluation.reason,
        });
      }
      continue;
    }

    unchangedEvents += 1;
  }

  const changeRate = replayedEvents > 0 ? changedEvents / replayedEvents : 0;
  return {
    totalEvents: events.length,
    replayedEvents,
    skippedEvents,
    changedEvents,
    unchangedEvents,
    changeRate,
    changes,
    posture: {
      current: {
        signals: currentSignals,
        score: calculateTrustPostureScore(currentSignals),
      },
      candidate: {
        signals: candidateSignals,
        score: calculateTrustPostureScore(candidateSignals),
      },
      drift: detectTrustDrift({ baseline: currentSignals, current: candidateSignals }),
    },
  };
}
