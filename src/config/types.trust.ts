export type TrustRiskLevel = "low" | "medium" | "high" | "critical" | "unknown";

export type TrustDataClassification =
  | "public"
  | "internal"
  | "confidential"
  | "restricted"
  | "secret";

export type TrustDecision = "allow" | "deny" | "step-up";

export type TrustPolicyLayer = "org" | "team" | "app" | "user" | "runtime";

export type TrustActorType = "human" | "agent" | "service";

export type TrustDestinationKind =
  | "none"
  | "chat"
  | "http"
  | "email"
  | "file"
  | "connector"
  | "tool";

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

export type TrustAuditConfig = {
  /** Persist trust audit logs (decision/approval/execution/delivery). Default: true. */
  enabled?: boolean;
  /** Optional path override for trust audit JSONL log. */
  path?: string;
  /** Fail closed when audit append fails. Default: true in enforce mode; false in simulate mode. */
  failClosed?: boolean;
  /** Include full payload snippets in audit events. */
  includePayload?: boolean;
};

export type TrustEmergencyControls = {
  /** Hard stop for trust-critical actions. */
  killSwitch?: boolean;
  /** Revoked outbound connectors/channels/targets (wildcards supported). */
  revokedDestinations?: string[];
  /** Quarantined skills disallowed for sensitive actions. */
  quarantinedSkills?: string[];
};

export type TrustExecRiskHints = {
  criticalPatterns?: string[];
  highPatterns?: string[];
  mediumPatterns?: string[];
};

export type TrustMessageRiskHints = {
  highRiskActions?: string[];
  criticalActions?: string[];
};

export type TrustRiskHints = {
  exec?: TrustExecRiskHints;
  message?: TrustMessageRiskHints;
};

export type TrustConfig = {
  /** Enable mandatory trust enforcement. Default: true. */
  enabled?: boolean;
  /** `enforce` blocks actions; `simulate` records decisions only. */
  mode?: "enforce" | "simulate";
  /** Tenant identifier used for trust scope binding and isolation. */
  tenantId?: string;
  /** Unknown risk fallback. Default: deny. */
  unknownRiskDecision?: "deny" | "step-up";
  /** Explicit outbound destination allowlist (wildcards supported). */
  outboundDestinationAllowlist?: string[];
  /** Default source data class when not explicitly inferred. */
  defaultDataClass?: TrustDataClassification;
  /** Hierarchical deterministic policy layers (runtime > user > app > team > org). */
  layers?: Partial<Record<TrustPolicyLayer, TrustPolicyRule[]>>;
  /** Audit chain controls. */
  audit?: TrustAuditConfig;
  /** Emergency controls for rapid containment. */
  emergency?: TrustEmergencyControls;
  /** Optional risk scoring hints (deterministic regex/action lists). */
  riskHints?: TrustRiskHints;
};
