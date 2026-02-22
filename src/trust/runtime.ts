import crypto from "node:crypto";
import type { OpenClawConfig } from "../config/config.js";
import type {
  TrustActorType,
  TrustConfig,
  TrustDataClassification,
  TrustDestinationKind,
  TrustPolicyLayer,
  TrustRiskLevel,
} from "../config/types.trust.js";
import { appendTrustAuditEvent } from "./audit-store.js";
import {
  evaluateTrustPolicy,
  inspectOutboundDlp,
  isDestinationAllowed,
  type TrustAction,
  type TrustApprovalGrant,
  type TrustDecisionChainStep,
  type TrustPolicyBundle,
  type TrustPolicyDecision,
  type TrustStage,
} from "./trust-plane.js";

const TRUST_DEFAULT_TENANT = "default";
const TRUST_DEFAULT_POLICY_VERSION = "trust-v1";

const DEFAULT_HIGH_RISK_MESSAGE_ACTIONS = new Set<string>([
  "delete",
  "unsend",
  "removeParticipant",
  "leaveGroup",
  "role-add",
  "role-remove",
  "timeout",
  "kick",
  "ban",
  "channel-delete",
  "category-delete",
]);

const DEFAULT_CRITICAL_MESSAGE_ACTIONS = new Set<string>([
  "ban",
  "channel-delete",
  "category-delete",
]);

const DEFAULT_EXEC_CRITICAL_PATTERNS = [
  /\brm\s+-rf\b/i,
  /\bmkfs\b/i,
  /\bdd\s+if=.*\bof=\/dev\//i,
  /\bshutdown\b/i,
  /\breboot\b/i,
  /\b:(){:|:&};:\b/i,
];

const DEFAULT_EXEC_HIGH_PATTERNS = [
  /\bcurl\b/i,
  /\bwget\b/i,
  /\bnc\b/i,
  /\bncat\b/i,
  /\bsocat\b/i,
  /\bscp\b/i,
  /\brsync\b/i,
  /\bssh\b/i,
  /\bchmod\s+777\b/i,
];

const DEFAULT_EXEC_MEDIUM_PATTERNS = [/\bcat\b/i, /\bfind\b/i, /\bgrep\b/i, /\btar\b/i, /\bzip\b/i];

const SECRET_DATA_PATTERNS = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bghp_[A-Za-z0-9]{36}\b/,
  /\b(?:token|api[_-]?key|secret)\b\s*[:=]/i,
];

const RESTRICTED_DATA_PATTERNS = [
  /\b(ssn|social security|passport|payment card|pci|hipaa|payroll|customer pii)\b/i,
  /\bconfidential\b/i,
];

const CONFIDENTIAL_DATA_PATTERNS = [/\binternal only\b/i, /\bprivate\b/i];

export type ResolvedTrustRuntimeConfig = {
  enabled: boolean;
  mode: "enforce" | "simulate";
  tenantId: string;
  defaultDataClass: TrustDataClassification;
  auditEnabled: boolean;
  auditFailClosed: boolean;
  auditIncludePayload: boolean;
  policy: TrustPolicyBundle;
  emergency: {
    killSwitch: boolean;
    revokedDestinations: string[];
    quarantinedSkills: string[];
  };
  riskHints: NonNullable<TrustConfig["riskHints"]>;
};

export type TrustGateResult = {
  decision: TrustPolicyDecision;
  blocked: boolean;
  simulatedViolation: boolean;
  mode: "enforce" | "simulate";
  auditEventId?: string;
};

function normalizeList(values?: string[]): string[] {
  if (!Array.isArray(values)) {
    return [];
  }
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of values) {
    if (typeof entry !== "string") {
      continue;
    }
    const trimmed = entry.trim();
    if (!trimmed) {
      continue;
    }
    const key = trimmed.toLowerCase();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(trimmed);
  }
  return out;
}

function cloneLayers(
  layers?: Partial<Record<TrustPolicyLayer, TrustConfig["layers"]["org"]>>,
): Partial<Record<TrustPolicyLayer, TrustPolicyBundle["layers"][TrustPolicyLayer]>> {
  if (!layers) {
    return {};
  }
  return {
    org: layers.org ? [...layers.org] : undefined,
    team: layers.team ? [...layers.team] : undefined,
    app: layers.app ? [...layers.app] : undefined,
    user: layers.user ? [...layers.user] : undefined,
    runtime: layers.runtime ? [...layers.runtime] : undefined,
  };
}

function resolveTrustConfigInput(params: {
  cfg?: OpenClawConfig;
  trustConfig?: TrustConfig;
}): TrustConfig | undefined {
  return params.trustConfig ?? params.cfg?.trust;
}

export function resolveTrustRuntimeConfig(params: {
  cfg?: OpenClawConfig;
  trustConfig?: TrustConfig;
}): ResolvedTrustRuntimeConfig {
  const configured = resolveTrustConfigInput(params);
  const mode = configured?.mode === "simulate" ? "simulate" : "enforce";
  const tenantId = configured?.tenantId?.trim() || TRUST_DEFAULT_TENANT;
  const defaultDataClass = configured?.defaultDataClass ?? "internal";
  const configuredLayers = cloneLayers(configured?.layers);

  const orgRules =
    configuredLayers.org && configuredLayers.org.length > 0
      ? configuredLayers.org
      : [
          {
            id: "baseline-allow",
            effect: "allow",
            reason: "Baseline deterministic allow; higher-priority deny/step-up rules still apply.",
          },
        ];

  const policy: TrustPolicyBundle = {
    version: TRUST_DEFAULT_POLICY_VERSION,
    layers: {
      org: orgRules,
      team: configuredLayers.team,
      app: configuredLayers.app,
      user: configuredLayers.user,
      runtime: configuredLayers.runtime,
    },
    unknownRiskDecision: configured?.unknownRiskDecision ?? "deny",
    outboundDestinationAllowlist:
      configured?.outboundDestinationAllowlist && configured.outboundDestinationAllowlist.length > 0
        ? normalizeList(configured.outboundDestinationAllowlist)
        : undefined,
  };

  return {
    enabled: configured?.enabled !== false,
    mode,
    tenantId,
    defaultDataClass,
    auditEnabled: configured?.audit?.enabled !== false,
    auditFailClosed: configured?.audit?.failClosed ?? mode === "enforce",
    auditIncludePayload: configured?.audit?.includePayload === true,
    policy,
    emergency: {
      killSwitch: configured?.emergency?.killSwitch === true,
      revokedDestinations: normalizeList(configured?.emergency?.revokedDestinations),
      quarantinedSkills: normalizeList(configured?.emergency?.quarantinedSkills),
    },
    riskHints: {
      exec: {
        criticalPatterns: normalizeList(configured?.riskHints?.exec?.criticalPatterns),
        highPatterns: normalizeList(configured?.riskHints?.exec?.highPatterns),
        mediumPatterns: normalizeList(configured?.riskHints?.exec?.mediumPatterns),
      },
      message: {
        highRiskActions: normalizeList(configured?.riskHints?.message?.highRiskActions),
        criticalActions: normalizeList(configured?.riskHints?.message?.criticalActions),
      },
    },
  };
}

function compileRegexes(patterns: string[]): RegExp[] {
  const regexes: RegExp[] = [];
  for (const pattern of patterns) {
    try {
      regexes.push(new RegExp(pattern, "i"));
    } catch {
      // Ignore invalid custom regex patterns and keep deterministic defaults.
    }
  }
  return regexes;
}

function matchesRegexes(text: string, regexes: RegExp[]): boolean {
  return regexes.some((pattern) => pattern.test(text));
}

export function inferTrustDataClass(params: {
  textPayload?: string;
  filePayloads?: string[];
  fallback?: TrustDataClassification;
}): TrustDataClassification {
  const fallback = params.fallback ?? "internal";
  const samples = [params.textPayload ?? "", ...(params.filePayloads ?? [])]
    .map((value) => value.trim())
    .filter(Boolean);
  if (samples.length === 0) {
    return fallback;
  }
  const joined = samples.join("\n");
  if (matchesRegexes(joined, SECRET_DATA_PATTERNS)) {
    return "secret";
  }
  if (matchesRegexes(joined, RESTRICTED_DATA_PATTERNS)) {
    return "restricted";
  }
  if (matchesRegexes(joined, CONFIDENTIAL_DATA_PATTERNS)) {
    return "confidential";
  }
  return fallback;
}

export function inferExecRisk(params: {
  command: string;
  riskHints?: NonNullable<TrustConfig["riskHints"]>["exec"];
}): TrustRiskLevel {
  const command = params.command.trim();
  if (!command) {
    return "unknown";
  }

  const customCritical = compileRegexes(normalizeList(params.riskHints?.criticalPatterns));
  const customHigh = compileRegexes(normalizeList(params.riskHints?.highPatterns));
  const customMedium = compileRegexes(normalizeList(params.riskHints?.mediumPatterns));

  if (matchesRegexes(command, [...customCritical, ...DEFAULT_EXEC_CRITICAL_PATTERNS])) {
    return "critical";
  }
  if (matchesRegexes(command, [...customHigh, ...DEFAULT_EXEC_HIGH_PATTERNS])) {
    return "high";
  }
  if (matchesRegexes(command, [...customMedium, ...DEFAULT_EXEC_MEDIUM_PATTERNS])) {
    return "medium";
  }
  return "low";
}

export function inferMessageRisk(params: {
  action: string;
  textPayload?: string;
  destinationTarget: string;
  riskHints?: NonNullable<TrustConfig["riskHints"]>["message"];
}): TrustRiskLevel {
  const action = params.action.trim().toLowerCase();
  const criticalActions = new Set<string>([
    ...DEFAULT_CRITICAL_MESSAGE_ACTIONS,
    ...normalizeList(params.riskHints?.criticalActions).map((entry) => entry.toLowerCase()),
  ]);
  const highActions = new Set<string>([
    ...DEFAULT_HIGH_RISK_MESSAGE_ACTIONS,
    ...normalizeList(params.riskHints?.highRiskActions).map((entry) => entry.toLowerCase()),
  ]);

  if (criticalActions.has(action)) {
    return "critical";
  }
  if (highActions.has(action)) {
    return "high";
  }

  const dlp = inspectOutboundDlp({ textPayload: params.textPayload });
  if (dlp.blocked) {
    return "high";
  }

  const destination = params.destinationTarget.trim().toLowerCase();
  if (destination.startsWith("http://") || destination.startsWith("https://")) {
    return "high";
  }

  return "low";
}

function sanitizeActorId(value: string | undefined | null): string {
  const trimmed = value?.trim();
  return trimmed && trimmed.length > 0 ? trimmed : "unknown-actor";
}

function resolveAudience(params: { explicitAudience?: string; destinationTarget: string }): string {
  const explicit = params.explicitAudience?.trim();
  if (explicit) {
    return explicit;
  }
  const target = params.destinationTarget.trim().toLowerCase();
  if (target.includes("channel") || target.includes("group") || target.includes("@g.us")) {
    return "group";
  }
  return "direct";
}

function normalizeDestinationKind(kind: TrustDestinationKind | undefined): TrustDestinationKind {
  return kind ?? "chat";
}

export function buildMessageTrustAction(params: {
  runtime: ResolvedTrustRuntimeConfig;
  action: string;
  stage: TrustStage;
  channel: string;
  destinationTarget: string;
  textPayload?: string;
  filePayloads?: string[];
  actorId?: string | null;
  actorType?: TrustActorType;
  sessionId?: string;
  membershipVersion?: string;
  roleVersion?: string;
  policyVersion?: string;
  sourceSystem?: string;
  sourceResource?: string;
  sourceDataClass?: TrustDataClassification;
  destinationKind?: TrustDestinationKind;
}): TrustAction {
  const now = Date.now();
  const dataClass =
    params.sourceDataClass ??
    inferTrustDataClass({
      textPayload: params.textPayload,
      filePayloads: params.filePayloads,
      fallback: params.runtime.defaultDataClass,
    });

  return {
    id: `msg-${crypto.randomUUID()}`,
    intent: `message:${params.action}`,
    operation: params.action,
    actor: {
      tenantId: params.runtime.tenantId,
      actorId: sanitizeActorId(params.actorId),
      actorType: params.actorType ?? (params.actorId ? "human" : "agent"),
      roleVersion: params.roleVersion,
    },
    source: {
      system: params.sourceSystem ?? "messaging",
      resource: params.sourceResource ?? params.channel,
      dataClass,
      tenantId: params.runtime.tenantId,
    },
    destination: {
      kind: normalizeDestinationKind(params.destinationKind),
      target: params.destinationTarget,
      destinationVersion: params.policyVersion ?? params.runtime.policy.version,
      dataClass,
    },
    context: {
      channel: params.channel,
      audience: resolveAudience({
        explicitAudience: undefined,
        destinationTarget: params.destinationTarget,
      }),
      sessionId: params.sessionId?.trim() || `session-${params.channel}`,
      occurredAtMs: now,
      membershipVersion: params.membershipVersion,
      policyVersion: params.policyVersion ?? params.runtime.policy.version,
    },
    risk: inferMessageRisk({
      action: params.action,
      textPayload: params.textPayload,
      destinationTarget: params.destinationTarget,
      riskHints: params.runtime.riskHints.message,
    }),
    stage: params.stage,
    textPayload: params.textPayload,
    filePayloads: params.filePayloads,
  };
}

export function buildExecTrustAction(params: {
  runtime: ResolvedTrustRuntimeConfig;
  command: string;
  stage: TrustStage;
  host: "sandbox" | "gateway" | "node";
  workdir: string;
  actorId?: string | null;
  actorType?: TrustActorType;
  sessionId?: string;
  channel?: string;
  audience?: string;
  roleVersion?: string;
  policyVersion?: string;
}): TrustAction {
  const now = Date.now();
  const dataClass = inferTrustDataClass({
    textPayload: params.command,
    fallback: params.runtime.defaultDataClass,
  });

  return {
    id: `exec-${crypto.randomUUID()}`,
    intent: `exec:${params.host}`,
    operation: "exec",
    actor: {
      tenantId: params.runtime.tenantId,
      actorId: sanitizeActorId(params.actorId),
      actorType: params.actorType ?? "agent",
      roleVersion: params.roleVersion,
    },
    source: {
      system: "exec",
      resource: params.workdir,
      dataClass,
      tenantId: params.runtime.tenantId,
    },
    destination: {
      kind: "tool",
      target: `exec:${params.host}`,
      destinationVersion: params.policyVersion ?? params.runtime.policy.version,
      dataClass,
    },
    context: {
      channel: params.channel?.trim() || "runtime",
      audience: params.audience?.trim() || "operator",
      sessionId: params.sessionId?.trim() || "exec-session",
      occurredAtMs: now,
      policyVersion: params.policyVersion ?? params.runtime.policy.version,
    },
    risk: inferExecRisk({ command: params.command, riskHints: params.runtime.riskHints.exec }),
    stage: params.stage,
    textPayload: params.command,
  };
}

function createSyntheticDecision(params: {
  decision: "allow" | "deny" | "step-up";
  reason: string;
  requirementIds: string[];
}): TrustPolicyDecision {
  const chain: TrustDecisionChainStep[] = [
    {
      phase: "policy",
      detail: params.reason,
      requirementIds: params.requirementIds,
    },
    {
      phase: "final",
      detail:
        params.decision === "allow"
          ? "Allowed by trust runtime precheck."
          : params.decision === "deny"
            ? "Denied by trust runtime precheck."
            : "Step-up required by trust runtime precheck.",
      requirementIds: params.requirementIds,
    },
  ];

  return {
    decision: params.decision,
    reason: params.reason,
    approval: {
      required: params.decision === "step-up",
      satisfied: false,
      dualControlRequired: false,
    },
    dlp: { blocked: false, reasons: [] },
    chain,
    explain: chain.map((entry) => `${entry.phase}: ${entry.detail}`).join(" | "),
  };
}

function shouldBlockInEnforceMode(decision: TrustPolicyDecision, stage: TrustStage): boolean {
  if (decision.decision === "deny") {
    return true;
  }
  return decision.decision === "step-up" && stage !== "proposal";
}

export function buildSyntheticApprovalGrant(params: {
  action: TrustAction;
  approvalId: string;
  approvers?: string[];
  scope?: "once" | "session" | "policy";
  nowMs?: number;
  ttlMs?: number;
}): TrustApprovalGrant {
  const nowMs = params.nowMs ?? Date.now();
  const ttlMs = params.ttlMs ?? 120_000;
  return {
    id: params.approvalId,
    scope: params.scope ?? "once",
    createdAtMs: nowMs,
    expiresAtMs: nowMs + Math.max(1, ttlMs),
    approvers:
      params.approvers && params.approvers.length > 0 ? [...params.approvers] : ["approval-system"],
    binding: {
      tenantId: params.action.actor.tenantId,
      actorId: params.action.actor.actorId,
      channel: params.action.context.channel,
      audience: params.action.context.audience,
      sourceDataClass: params.action.source.dataClass,
      destinationKind: params.action.destination.kind,
      destinationTarget: params.action.destination.target,
      policyVersion: params.action.context.policyVersion ?? TRUST_DEFAULT_POLICY_VERSION,
      sessionId: params.action.context.sessionId,
      membershipVersion: params.action.context.membershipVersion,
      roleVersion: params.action.actor.roleVersion,
      destinationVersion: params.action.destination.destinationVersion,
    },
  };
}

async function writeTrustAudit(params: {
  runtime: ResolvedTrustRuntimeConfig;
  cfg?: OpenClawConfig;
  trustConfig?: TrustConfig;
  action: TrustAction;
  decision: TrustPolicyDecision;
}): Promise<string | undefined> {
  if (!params.runtime.auditEnabled) {
    return undefined;
  }

  const payload: Record<string, unknown> = {
    stage: params.action.stage,
    intent: params.action.intent,
    operation: params.action.operation,
    risk: params.action.risk,
    decision: params.decision.decision,
    reason: params.decision.reason,
    matchedRuleId: params.decision.matchedRuleId ?? null,
    approval: params.decision.approval,
    dlp: params.decision.dlp,
    chain: params.decision.chain,
    actor: {
      actorType: params.action.actor.actorType,
      roleVersion: params.action.actor.roleVersion ?? null,
      roles: params.action.actor.roles ?? [],
    },
    context: {
      channel: params.action.context.channel,
      audience: params.action.context.audience,
      sessionId: params.action.context.sessionId,
      occurredAtMs: params.action.context.occurredAtMs,
      membershipVersion: params.action.context.membershipVersion ?? null,
      policyVersion: params.action.context.policyVersion ?? null,
    },
    source: {
      system: params.action.source.system,
      resource: params.action.source.resource,
      dataClass: params.action.source.dataClass,
    },
    destination: {
      kind: params.action.destination.kind,
      target: params.action.destination.target,
      dataClass: params.action.destination.dataClass ?? null,
    },
    mode: params.runtime.mode,
  };

  if (params.runtime.auditIncludePayload) {
    payload.textPayload = params.action.textPayload ?? null;
    payload.filePayloads = params.action.filePayloads ?? [];
  }

  const kind =
    params.action.stage === "proposal"
      ? "decision"
      : params.action.stage === "execution"
        ? "execution"
        : "delivery";

  const event = await appendTrustAuditEvent({
    cfg: params.cfg ? { ...params.cfg, trust: params.trustConfig ?? params.cfg.trust } : undefined,
    overridePath: params.trustConfig?.audit?.path,
    kind,
    tsMs: params.action.context.occurredAtMs,
    tenantId: params.action.actor.tenantId,
    actorId: params.action.actor.actorId,
    actionId: params.action.id,
    payload,
  });
  return event.id;
}

export async function recordTrustApprovalEvent(params: {
  cfg?: OpenClawConfig;
  trustConfig?: TrustConfig;
  action: TrustAction;
  approvalId: string;
  decision: "allow-once" | "allow-always" | "deny";
  resolvedBy?: string | null;
  resolvedByDeviceId?: string | null;
  resolvedByClientId?: string | null;
  approvers?: string[];
  scope?: "once" | "session" | "policy";
}): Promise<string | undefined> {
  const runtime = resolveTrustRuntimeConfig({ cfg: params.cfg, trustConfig: params.trustConfig });
  if (!runtime.auditEnabled) {
    return undefined;
  }

  const event = await appendTrustAuditEvent({
    cfg: params.cfg ? { ...params.cfg, trust: params.trustConfig ?? params.cfg.trust } : undefined,
    overridePath: params.trustConfig?.audit?.path,
    kind: "approval",
    tsMs: Date.now(),
    tenantId: params.action.actor.tenantId,
    actorId: params.action.actor.actorId,
    actionId: params.action.id,
    payload: {
      approvalId: params.approvalId,
      decision: params.decision,
      resolvedBy: params.resolvedBy ?? null,
      resolvedByDeviceId: params.resolvedByDeviceId ?? null,
      resolvedByClientId: params.resolvedByClientId ?? null,
      approvers: params.approvers ?? [],
      scope: params.scope ?? "once",
      stage: params.action.stage,
      operation: params.action.operation,
    },
  });

  return event.id;
}

export async function evaluateTrustGate(params: {
  cfg?: OpenClawConfig;
  trustConfig?: TrustConfig;
  action: TrustAction;
  approvals?: TrustApprovalGrant[];
  consumedApprovalIds?: ReadonlySet<string>;
  nowMs?: number;
}): Promise<TrustGateResult> {
  const runtime = resolveTrustRuntimeConfig({ cfg: params.cfg, trustConfig: params.trustConfig });

  if (!runtime.enabled) {
    return {
      decision: createSyntheticDecision({
        decision: "allow",
        reason: "Trust plane disabled by configuration.",
        requirementIds: ["REQ-021"],
      }),
      blocked: false,
      simulatedViolation: false,
      mode: runtime.mode,
    };
  }

  const nowMs = params.nowMs ?? Date.now();
  const action: TrustAction = {
    ...params.action,
    actor: {
      ...params.action.actor,
      tenantId: params.action.actor.tenantId?.trim() || runtime.tenantId,
      actorId: sanitizeActorId(params.action.actor.actorId),
    },
    context: {
      ...params.action.context,
      policyVersion: params.action.context.policyVersion ?? runtime.policy.version,
    },
  };

  let decision: TrustPolicyDecision;

  if (runtime.emergency.killSwitch) {
    decision = createSyntheticDecision({
      decision: "deny",
      reason: "Trust emergency kill switch is active.",
      requirementIds: ["REQ-018", "INV-01"],
    });
  } else if (
    action.stage === "outbound" &&
    runtime.emergency.revokedDestinations.length > 0 &&
    isDestinationAllowed(action.destination.target, runtime.emergency.revokedDestinations)
  ) {
    decision = createSyntheticDecision({
      decision: "deny",
      reason: `Destination ${action.destination.target} is revoked by emergency controls.`,
      requirementIds: ["REQ-018", "REQ-014"],
    });
  } else {
    decision = evaluateTrustPolicy({
      action,
      policy: runtime.policy,
      approvals: params.approvals,
      consumedApprovalIds: params.consumedApprovalIds,
      nowMs,
    });
  }

  let auditEventId: string | undefined;
  try {
    auditEventId = await writeTrustAudit({
      runtime,
      cfg: params.cfg,
      trustConfig: params.trustConfig,
      action,
      decision,
    });
  } catch (err) {
    if (runtime.auditFailClosed) {
      throw new Error(`Trust audit append failed: ${String(err)}`, { cause: err });
    }
  }

  const enforceBlock = shouldBlockInEnforceMode(decision, action.stage);
  const simulatedViolation = enforceBlock;
  const blocked = runtime.mode === "enforce" ? enforceBlock : false;

  return {
    decision,
    blocked,
    simulatedViolation,
    mode: runtime.mode,
    auditEventId,
  };
}
