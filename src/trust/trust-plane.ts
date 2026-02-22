import crypto from "node:crypto";

export const TRUST_POLICY_LAYERS = ["org", "team", "app", "user", "runtime"] as const;
export type TrustPolicyLayer = (typeof TRUST_POLICY_LAYERS)[number];

const TRUST_LAYER_PRECEDENCE: Record<TrustPolicyLayer, number> = {
  runtime: 5,
  user: 4,
  app: 3,
  team: 2,
  org: 1,
};

export type TrustRiskLevel = "low" | "medium" | "high" | "critical" | "unknown";
export type TrustDataClassification =
  | "public"
  | "internal"
  | "confidential"
  | "restricted"
  | "secret";
export type TrustDecision = "allow" | "deny" | "step-up";
export type TrustStage = "proposal" | "execution" | "outbound";

export type TrustActorType = "human" | "agent" | "service";

export type TrustActor = {
  tenantId: string;
  actorId: string;
  actorType: TrustActorType;
  roleVersion?: string;
  roles?: string[];
};

export type TrustDataSource = {
  system: string;
  resource: string;
  dataClass: TrustDataClassification;
  tenantId?: string;
};

export type TrustDestinationKind =
  | "none"
  | "chat"
  | "http"
  | "email"
  | "file"
  | "connector"
  | "tool";

export type TrustDestination = {
  kind: TrustDestinationKind;
  target: string;
  category?: string;
  dataClass?: TrustDataClassification;
  destinationVersion?: string;
};

export type TrustContext = {
  channel: string;
  audience: string;
  sessionId: string;
  occurredAtMs: number;
  membershipVersion?: string;
  policyVersion?: string;
};

export type TrustAction = {
  id: string;
  intent: string;
  operation: string;
  actor: TrustActor;
  source: TrustDataSource;
  destination: TrustDestination;
  context: TrustContext;
  risk: TrustRiskLevel;
  stage: TrustStage;
  textPayload?: string;
  filePayloads?: string[];
};

export type TrustPolicyMatch = {
  actorIds?: string[];
  actorTypes?: TrustActorType[];
  intents?: string[];
  operations?: string[];
  channels?: string[];
  audiences?: string[];
  sourceDataClasses?: TrustDataClassification[];
  destinationKinds?: TrustDestinationKind[];
  destinationTargets?: string[];
  riskLevels?: TrustRiskLevel[];
};

export type TrustPolicyRule = {
  id: string;
  effect: TrustDecision;
  reason: string;
  priority?: number;
  dualControl?: boolean;
  match?: TrustPolicyMatch;
};

export type TrustPolicyBundle = {
  version: string;
  layers: Partial<Record<TrustPolicyLayer, TrustPolicyRule[]>>;
  outboundDestinationAllowlist?: string[];
  unknownRiskDecision?: "deny" | "step-up";
};

export type TrustApprovalScope = "once" | "session" | "policy";

export type TrustApprovalBinding = {
  tenantId: string;
  actorId: string;
  channel: string;
  audience: string;
  sourceDataClass: TrustDataClassification;
  destinationKind: TrustDestinationKind;
  destinationTarget: string;
  policyVersion: string;
  sessionId?: string;
  membershipVersion?: string;
  roleVersion?: string;
  destinationVersion?: string;
};

export type TrustApprovalGrant = {
  id: string;
  scope: TrustApprovalScope;
  createdAtMs: number;
  expiresAtMs: number;
  approvers: string[];
  binding: TrustApprovalBinding;
  usedAtMs?: number;
};

export type TrustDecisionChainStep = {
  phase: "validation" | "policy" | "approval" | "dlp" | "final";
  detail: string;
  requirementIds: string[];
};

export type TrustDlpResult = {
  blocked: boolean;
  reasons: string[];
};

export type TrustPolicyDecision = {
  decision: TrustDecision;
  reason: string;
  matchedRuleId?: string;
  approval: {
    required: boolean;
    satisfied: boolean;
    dualControlRequired: boolean;
    grantId?: string;
    failureReason?: string;
  };
  dlp: TrustDlpResult;
  chain: TrustDecisionChainStep[];
  explain: string;
};

type MatchedRule = {
  layer: TrustPolicyLayer;
  rule: TrustPolicyRule;
};

type ApprovalValidationResult =
  | {
      ok: true;
      grant: TrustApprovalGrant;
    }
  | {
      ok: false;
      reason: string;
    };

const RISK_RANK: Record<Exclude<TrustRiskLevel, "unknown">, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const EXFIL_PATTERNS: Array<{ id: string; pattern: RegExp; reason: string }> = [
  {
    id: "direct-upload",
    pattern:
      /\b(curl|wget)\b[^\n]*(--data\b|-d\b|--data-binary\b|-F\b|--form\b)[^\n]*@[^\n]*(https?:\/\/|ftp:\/\/)/i,
    reason: "Direct upload pattern detected (data/file posted to remote destination).",
  },
  {
    id: "piped-encoded-exfil",
    pattern: /\|\s*(base64|xxd|openssl\s+enc)\b[^\n]*\|\s*(curl|wget|nc|ncat|socat)\b/i,
    reason: "Encoded + piped exfiltration pattern detected.",
  },
  {
    id: "chunked-exfil",
    pattern: /\b(split\b|dd\s+if=|chunk\w*)\b[^\n]*(curl|wget|nc|ncat|upload)\b/i,
    reason: "Chunked exfiltration pattern detected.",
  },
  {
    id: "ssh-key-leak",
    pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
    reason: "Private key material detected in outbound payload.",
  },
  {
    id: "aws-key-leak",
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    reason: "AWS access key pattern detected in outbound payload.",
  },
  {
    id: "github-token-leak",
    pattern: /\bghp_[A-Za-z0-9]{36}\b/,
    reason: "GitHub token pattern detected in outbound payload.",
  },
];

function riskAtLeast(level: TrustRiskLevel, minimum: Exclude<TrustRiskLevel, "unknown">): boolean {
  if (level === "unknown") {
    return false;
  }
  return RISK_RANK[level] >= RISK_RANK[minimum];
}

function isHighRisk(level: TrustRiskLevel): boolean {
  return level === "high" || level === "critical";
}

function isRestrictedData(level: TrustDataClassification): boolean {
  return level === "restricted" || level === "secret";
}

function normalizePattern(pattern: string): string {
  return pattern.trim().toLowerCase();
}

function wildcardMatch(value: string, pattern: string): boolean {
  const normalizedValue = value.trim().toLowerCase();
  const normalizedPattern = normalizePattern(pattern);
  if (normalizedPattern === "*") {
    return true;
  }
  if (!normalizedPattern.includes("*")) {
    return normalizedValue === normalizedPattern;
  }
  const escaped = normalizedPattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*");
  const regex = new RegExp(`^${escaped}$`, "i");
  return regex.test(normalizedValue);
}

function matchList(value: string, patterns?: string[]): boolean {
  if (!patterns || patterns.length === 0) {
    return true;
  }
  return patterns.some((pattern) => wildcardMatch(value, pattern));
}

function matchEnum<T extends string>(value: T, patterns?: T[]): boolean {
  if (!patterns || patterns.length === 0) {
    return true;
  }
  return patterns.includes(value);
}

function ruleMatches(action: TrustAction, rule: TrustPolicyRule): boolean {
  const match = rule.match;
  if (!match) {
    return true;
  }

  if (!matchList(action.actor.actorId, match.actorIds)) {
    return false;
  }
  if (!matchEnum(action.actor.actorType, match.actorTypes)) {
    return false;
  }
  if (!matchList(action.intent, match.intents)) {
    return false;
  }
  if (!matchList(action.operation, match.operations)) {
    return false;
  }
  if (!matchList(action.context.channel, match.channels)) {
    return false;
  }
  if (!matchList(action.context.audience, match.audiences)) {
    return false;
  }
  if (!matchEnum(action.source.dataClass, match.sourceDataClasses)) {
    return false;
  }
  if (!matchEnum(action.destination.kind, match.destinationKinds)) {
    return false;
  }
  if (!matchList(action.destination.target, match.destinationTargets)) {
    return false;
  }
  if (!matchEnum(action.risk, match.riskLevels)) {
    return false;
  }
  return true;
}

function sortMatchedRules(a: MatchedRule, b: MatchedRule): number {
  const layerDiff = TRUST_LAYER_PRECEDENCE[b.layer] - TRUST_LAYER_PRECEDENCE[a.layer];
  if (layerDiff !== 0) {
    return layerDiff;
  }
  const priorityA = a.rule.priority ?? 0;
  const priorityB = b.rule.priority ?? 0;
  if (priorityA !== priorityB) {
    return priorityB - priorityA;
  }
  return a.rule.id.localeCompare(b.rule.id);
}

function selectBestRule(matches: MatchedRule[], effect: TrustDecision): MatchedRule | null {
  const filtered = matches
    .filter((entry) => entry.rule.effect === effect)
    .toSorted(sortMatchedRules);
  return filtered.length > 0 ? filtered[0] : null;
}

function collectMatchingRules(action: TrustAction, policy: TrustPolicyBundle): MatchedRule[] {
  const matched: MatchedRule[] = [];
  for (const layer of TRUST_POLICY_LAYERS) {
    const rules = policy.layers[layer] ?? [];
    for (const rule of rules) {
      if (ruleMatches(action, rule)) {
        matched.push({ layer, rule });
      }
    }
  }
  return matched;
}

function validateActionModel(action: TrustAction): string[] {
  const missing: string[] = [];
  if (!action.actor.actorId.trim()) {
    missing.push("actor.actorId");
  }
  if (!action.intent.trim()) {
    missing.push("intent");
  }
  if (!action.source.resource.trim()) {
    missing.push("source.resource");
  }
  if (!action.operation.trim()) {
    missing.push("operation");
  }
  if (!action.destination.target.trim()) {
    missing.push("destination.target");
  }
  if (!action.context.channel.trim()) {
    missing.push("context.channel");
  }
  if (!action.context.audience.trim()) {
    missing.push("context.audience");
  }
  return missing;
}

export function inspectOutboundDlp(params: {
  textPayload?: string;
  filePayloads?: string[];
}): TrustDlpResult {
  const snippets = [params.textPayload ?? "", ...(params.filePayloads ?? [])]
    .map((value) => value.trim())
    .filter(Boolean);
  if (snippets.length === 0) {
    return { blocked: false, reasons: [] };
  }
  const joined = snippets.join("\n");
  const reasons = EXFIL_PATTERNS.filter((entry) => entry.pattern.test(joined)).map(
    (entry) => `${entry.id}: ${entry.reason}`,
  );
  return { blocked: reasons.length > 0, reasons };
}

export function isDestinationAllowed(target: string, allowlist?: string[]): boolean {
  if (!allowlist || allowlist.length === 0) {
    return true;
  }
  return allowlist.some((entry) => wildcardMatch(target, entry));
}

function uniqueNonEmpty(values: string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const value of values) {
    const normalized = value.trim().toLowerCase();
    if (!normalized || seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    result.push(normalized);
  }
  return result;
}

function validateApprovalGrant(params: {
  action: TrustAction;
  policyVersion: string;
  approval: TrustApprovalGrant;
  nowMs: number;
  dualControlRequired: boolean;
  consumedApprovalIds?: ReadonlySet<string>;
}): ApprovalValidationResult {
  const { action, policyVersion, approval, nowMs, dualControlRequired, consumedApprovalIds } =
    params;

  if (approval.expiresAtMs <= nowMs) {
    return { ok: false, reason: "approval expired" };
  }

  if (approval.usedAtMs && approval.scope === "once") {
    return { ok: false, reason: "approval already consumed" };
  }

  if (consumedApprovalIds?.has(approval.id) && approval.scope === "once") {
    return { ok: false, reason: "approval already consumed in this execution context" };
  }

  if (approval.binding.policyVersion !== policyVersion) {
    return { ok: false, reason: "policy version drifted" };
  }

  if (approval.binding.tenantId !== action.actor.tenantId) {
    return { ok: false, reason: "tenant mismatch" };
  }

  if (approval.binding.actorId !== action.actor.actorId) {
    return { ok: false, reason: "actor mismatch" };
  }

  if (approval.binding.channel !== action.context.channel) {
    return { ok: false, reason: "channel mismatch" };
  }

  if (approval.binding.audience !== action.context.audience) {
    return { ok: false, reason: "audience mismatch" };
  }

  if (approval.binding.sourceDataClass !== action.source.dataClass) {
    return { ok: false, reason: "data classification mismatch" };
  }

  if (approval.binding.destinationKind !== action.destination.kind) {
    return { ok: false, reason: "destination kind mismatch" };
  }

  if (!wildcardMatch(action.destination.target, approval.binding.destinationTarget)) {
    return { ok: false, reason: "destination mismatch" };
  }

  if (approval.scope === "session" && approval.binding.sessionId !== action.context.sessionId) {
    return { ok: false, reason: "session mismatch" };
  }

  if (
    approval.binding.membershipVersion &&
    approval.binding.membershipVersion !== action.context.membershipVersion
  ) {
    return { ok: false, reason: "membership context drifted" };
  }

  if (approval.binding.roleVersion && approval.binding.roleVersion !== action.actor.roleVersion) {
    return { ok: false, reason: "role context drifted" };
  }

  if (
    approval.binding.destinationVersion &&
    approval.binding.destinationVersion !== action.destination.destinationVersion
  ) {
    return { ok: false, reason: "destination context drifted" };
  }

  if (dualControlRequired && uniqueNonEmpty(approval.approvers).length < 2) {
    return { ok: false, reason: "dual-control requirement not satisfied" };
  }

  return { ok: true, grant: approval };
}

function findValidApproval(params: {
  action: TrustAction;
  policyVersion: string;
  approvals?: TrustApprovalGrant[];
  nowMs: number;
  dualControlRequired: boolean;
  consumedApprovalIds?: ReadonlySet<string>;
}): ApprovalValidationResult {
  const approvals = params.approvals ?? [];
  if (approvals.length === 0) {
    return { ok: false, reason: "no approvals provided" };
  }

  let firstFailure = "no approval matched";
  for (const approval of approvals) {
    const validation = validateApprovalGrant({
      action: params.action,
      policyVersion: params.policyVersion,
      approval,
      nowMs: params.nowMs,
      dualControlRequired: params.dualControlRequired,
      consumedApprovalIds: params.consumedApprovalIds,
    });
    if (validation.ok) {
      return validation;
    }
    firstFailure = validation.reason;
  }

  return { ok: false, reason: firstFailure };
}

function explainChain(chain: TrustDecisionChainStep[]): string {
  return chain.map((entry) => `${entry.phase}: ${entry.detail}`).join(" | ");
}

function pushChain(
  chain: TrustDecisionChainStep[],
  phase: TrustDecisionChainStep["phase"],
  detail: string,
  requirementIds: string[],
) {
  chain.push({ phase, detail, requirementIds });
}

function choosePolicyDecision(matches: MatchedRule[]): {
  decision: TrustDecision;
  reason: string;
  matched?: MatchedRule;
} {
  const deny = selectBestRule(matches, "deny");
  if (deny) {
    return {
      decision: "deny",
      reason: `Denied by ${deny.layer}.${deny.rule.id}: ${deny.rule.reason}`,
      matched: deny,
    };
  }

  const stepUp = selectBestRule(matches, "step-up");
  if (stepUp) {
    return {
      decision: "step-up",
      reason: `Step-up required by ${stepUp.layer}.${stepUp.rule.id}: ${stepUp.rule.reason}`,
      matched: stepUp,
    };
  }

  const allow = selectBestRule(matches, "allow");
  if (allow) {
    return {
      decision: "allow",
      reason: `Allowed by ${allow.layer}.${allow.rule.id}: ${allow.rule.reason}`,
      matched: allow,
    };
  }

  return {
    decision: "deny",
    reason: "Denied by default (no matching allow rule).",
    matched: undefined,
  };
}

export function evaluateTrustPolicy(params: {
  action: TrustAction;
  policy: TrustPolicyBundle;
  approvals?: TrustApprovalGrant[];
  nowMs?: number;
  consumedApprovalIds?: ReadonlySet<string>;
}): TrustPolicyDecision {
  const nowMs = params.nowMs ?? Date.now();
  const chain: TrustDecisionChainStep[] = [];

  const missingFields = validateActionModel(params.action);
  if (missingFields.length > 0) {
    const reason = `Action model missing required fields: ${missingFields.join(", ")}.`;
    pushChain(chain, "validation", reason, ["REQ-001", "REQ-002"]);
    pushChain(chain, "final", "Denied: invalid action model.", ["INV-01", "REQ-003"]);
    return {
      decision: "deny",
      reason,
      approval: {
        required: false,
        satisfied: false,
        dualControlRequired: false,
      },
      dlp: { blocked: false, reasons: [] },
      chain,
      explain: explainChain(chain),
    };
  }

  if (params.action.risk === "unknown") {
    const unknownRiskDecision = params.policy.unknownRiskDecision ?? "deny";
    const reason =
      unknownRiskDecision === "step-up"
        ? "Unknown risk requires step-up approval."
        : "Unknown risk denied by policy.";
    pushChain(chain, "policy", reason, ["INV-05", "REQ-003"]);

    if (unknownRiskDecision === "deny") {
      pushChain(chain, "final", "Denied: unknown risk.", ["INV-05"]);
      return {
        decision: "deny",
        reason,
        approval: {
          required: false,
          satisfied: false,
          dualControlRequired: false,
        },
        dlp: { blocked: false, reasons: [] },
        chain,
        explain: explainChain(chain),
      };
    }
  }

  const matched = collectMatchingRules(params.action, params.policy);
  const base = choosePolicyDecision(matched);
  pushChain(chain, "policy", base.reason, ["INV-01", "REQ-003", "REQ-004"]);

  const restrictedData = isRestrictedData(params.action.source.dataClass);
  const destinationData = params.action.destination.dataClass;
  const restrictedDestinationData = destinationData ? isRestrictedData(destinationData) : false;
  const ruleDualControl = matched.some((entry) => entry.rule.dualControl === true);
  const dualControlRequired = ruleDualControl || restrictedData || restrictedDestinationData;

  let decision = base.decision;
  let reason = base.reason;

  if (decision !== "deny" && isHighRisk(params.action.risk)) {
    decision = "step-up";
    reason = `High-risk action (${params.action.risk}) requires step-up approval.`;
    pushChain(chain, "policy", reason, ["INV-01", "REQ-008", "REQ-020"]);
  }

  if (decision !== "deny" && params.action.stage === "outbound") {
    const destinationAllowed = isDestinationAllowed(
      params.action.destination.target,
      params.policy.outboundDestinationAllowlist,
    );
    if (!destinationAllowed) {
      reason = `Destination ${params.action.destination.target} is not in outbound allowlist.`;
      pushChain(chain, "policy", reason, ["REQ-014", "REQ-003"]);
      pushChain(chain, "final", "Denied: outbound destination blocked.", ["INV-01", "REQ-014"]);
      return {
        decision: "deny",
        reason,
        matchedRuleId: base.matched?.rule.id,
        approval: {
          required: false,
          satisfied: false,
          dualControlRequired,
        },
        dlp: { blocked: false, reasons: [] },
        chain,
        explain: explainChain(chain),
      };
    }
  }

  const dlp =
    params.action.stage === "outbound"
      ? inspectOutboundDlp({
          textPayload: params.action.textPayload,
          filePayloads: params.action.filePayloads,
        })
      : { blocked: false, reasons: [] };

  if (dlp.blocked) {
    reason = dlp.reasons.join("; ");
    pushChain(chain, "dlp", reason, ["REQ-007", "REQ-015", "GATE-004"]);
    pushChain(chain, "final", "Denied: outbound DLP blocked potential exfiltration.", ["INV-01"]);
    return {
      decision: "deny",
      reason,
      matchedRuleId: base.matched?.rule.id,
      approval: {
        required: false,
        satisfied: false,
        dualControlRequired,
      },
      dlp,
      chain,
      explain: explainChain(chain),
    };
  }

  if (decision === "deny") {
    pushChain(chain, "final", "Denied by deterministic policy decision.", ["INV-01", "REQ-003"]);
    return {
      decision: "deny",
      reason,
      matchedRuleId: base.matched?.rule.id,
      approval: {
        required: false,
        satisfied: false,
        dualControlRequired,
      },
      dlp,
      chain,
      explain: explainChain(chain),
    };
  }

  if (decision === "allow") {
    pushChain(chain, "final", `Allowed at ${params.action.stage} stage.`, ["INV-01", "REQ-005"]);
    return {
      decision: "allow",
      reason,
      matchedRuleId: base.matched?.rule.id,
      approval: {
        required: false,
        satisfied: false,
        dualControlRequired,
      },
      dlp,
      chain,
      explain: explainChain(chain),
    };
  }

  const approval = findValidApproval({
    action: params.action,
    policyVersion: params.policy.version,
    approvals: params.approvals,
    nowMs,
    dualControlRequired,
    consumedApprovalIds: params.consumedApprovalIds,
  });

  if (!approval.ok) {
    pushChain(chain, "approval", `Approval missing/invalid: ${approval.reason}.`, [
      "INV-02",
      "REQ-008",
      "REQ-009",
      "REQ-010",
    ]);

    const pendingDecision: TrustDecision = params.action.stage === "proposal" ? "step-up" : "deny";
    pushChain(
      chain,
      "final",
      pendingDecision === "step-up"
        ? "Step-up approval required before execution."
        : "Denied: execution/outbound attempted without valid approval.",
      ["INV-01", "REQ-005"],
    );

    return {
      decision: pendingDecision,
      reason,
      matchedRuleId: base.matched?.rule.id,
      approval: {
        required: true,
        satisfied: false,
        dualControlRequired,
        failureReason: approval.reason,
      },
      dlp,
      chain,
      explain: explainChain(chain),
    };
  }

  pushChain(chain, "approval", `Valid approval ${approval.grant.id} matched current context.`, [
    "INV-02",
    "REQ-008",
    "REQ-009",
    "REQ-010",
  ]);
  pushChain(chain, "final", "Allowed with valid context-bound approval.", ["INV-01", "REQ-005"]);

  return {
    decision: "allow",
    reason,
    matchedRuleId: base.matched?.rule.id,
    approval: {
      required: true,
      satisfied: true,
      dualControlRequired,
      grantId: approval.grant.id,
    },
    dlp,
    chain,
    explain: explainChain(chain),
  };
}

export type TrustAuditEventKind = "decision" | "approval" | "execution" | "delivery";

export type TrustAuditEvent = {
  id: string;
  kind: TrustAuditEventKind;
  tsMs: number;
  tenantId: string;
  actorId: string;
  actionId: string;
  payload: Record<string, unknown>;
  previousHash: string | null;
  hash: string;
};

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>).toSorted(([a], [b]) =>
    a.localeCompare(b),
  );
  const body = entries
    .map(([key, entryValue]) => `${JSON.stringify(key)}:${canonicalJson(entryValue)}`)
    .join(",");
  return `{${body}}`;
}

function computeAuditHash(event: Omit<TrustAuditEvent, "hash">): string {
  return crypto.createHash("sha256").update(canonicalJson(event)).digest("hex");
}

export function createTrustAuditEvent(params: {
  id: string;
  kind: TrustAuditEventKind;
  tsMs: number;
  tenantId: string;
  actorId: string;
  actionId: string;
  payload: Record<string, unknown>;
  previousHash: string | null;
}): TrustAuditEvent {
  const eventWithoutHash: Omit<TrustAuditEvent, "hash"> = {
    id: params.id,
    kind: params.kind,
    tsMs: params.tsMs,
    tenantId: params.tenantId,
    actorId: params.actorId,
    actionId: params.actionId,
    payload: params.payload,
    previousHash: params.previousHash,
  };

  return {
    ...eventWithoutHash,
    hash: computeAuditHash(eventWithoutHash),
  };
}

export function verifyTrustAuditChain(events: TrustAuditEvent[]): {
  valid: boolean;
  error?: string;
  index?: number;
} {
  let expectedPreviousHash: string | null = null;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];

    if (event.previousHash !== expectedPreviousHash) {
      return {
        valid: false,
        index,
        error: `previousHash mismatch at index ${index}`,
      };
    }

    const { hash, ...withoutHash } = event;
    const expectedHash = computeAuditHash(withoutHash);
    if (hash !== expectedHash) {
      return {
        valid: false,
        index,
        error: `hash mismatch at index ${index}`,
      };
    }

    expectedPreviousHash = event.hash;
  }

  return { valid: true };
}

export type TrustPostureSignals = {
  denyByDefault: boolean;
  stagedChecks: boolean;
  contextBoundApprovals: boolean;
  outboundAllowlist: boolean;
  outboundDlp: boolean;
  immutableAuditChain: boolean;
  dualControl: boolean;
};

export function calculateTrustPostureScore(signals: TrustPostureSignals): number {
  const weights: Record<keyof TrustPostureSignals, number> = {
    denyByDefault: 20,
    stagedChecks: 15,
    contextBoundApprovals: 20,
    outboundAllowlist: 15,
    outboundDlp: 15,
    immutableAuditChain: 10,
    dualControl: 5,
  };

  let score = 0;
  for (const key of Object.keys(weights) as Array<keyof TrustPostureSignals>) {
    if (signals[key]) {
      score += weights[key];
    }
  }

  return Math.min(100, Math.max(0, score));
}

export function detectTrustDrift(params: {
  baseline: TrustPostureSignals;
  current: TrustPostureSignals;
}): Array<keyof TrustPostureSignals> {
  const drift: Array<keyof TrustPostureSignals> = [];
  const keys = Object.keys(params.baseline) as Array<keyof TrustPostureSignals>;
  for (const key of keys) {
    if (params.baseline[key] && !params.current[key]) {
      drift.push(key);
    }
  }
  return drift;
}

export function shouldStepUpForUnknownRisk(params: {
  action: TrustAction;
  policy: TrustPolicyBundle;
}): boolean {
  return params.action.risk === "unknown" && params.policy.unknownRiskDecision === "step-up";
}

export function shouldRequireStepUpForRisk(action: TrustAction): boolean {
  return riskAtLeast(action.risk, "high") || action.risk === "unknown";
}
