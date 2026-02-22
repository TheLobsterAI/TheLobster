import type { ExecAsk, ExecSecurity } from "../infra/exec-approvals.js";
import {
  DEFAULT_APPROVAL_REQUEST_TIMEOUT_MS,
  DEFAULT_APPROVAL_TIMEOUT_MS,
} from "./bash-tools.exec-runtime.js";
import { callGatewayTool } from "./tools/gateway.js";

export type ExecApprovalDecisionValue = "allow-once" | "allow-always" | "deny";

export type ExecApprovalDecisionResult = {
  decision: ExecApprovalDecisionValue | null;
  resolvedBy: string | null;
  resolvedByDeviceId: string | null;
  resolvedByClientId: string | null;
  approvers: string[];
};

export type RequestExecApprovalDecisionParams = {
  id: string;
  command: string;
  cwd: string;
  host: "gateway" | "node";
  security: ExecSecurity;
  ask: ExecAsk;
  agentId?: string;
  resolvedPath?: string;
  sessionKey?: string;
};

function normalizeOptionalString(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizeDecision(value: unknown): ExecApprovalDecisionValue | null {
  if (value === "allow-once" || value === "allow-always" || value === "deny") {
    return value;
  }
  return null;
}

function uniqueNonEmpty(values: Array<string | null | undefined>): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const normalized = normalizeOptionalString(value);
    if (!normalized) {
      continue;
    }
    const key = normalized.toLowerCase();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(normalized);
  }
  return out;
}

export async function requestExecApprovalDecision(
  params: RequestExecApprovalDecisionParams,
): Promise<ExecApprovalDecisionResult> {
  const decisionResult = await callGatewayTool<{
    decision?: unknown;
    resolvedBy?: unknown;
    resolvedByDeviceId?: unknown;
    resolvedByClientId?: unknown;
    approvers?: unknown;
  }>(
    "exec.approval.request",
    { timeoutMs: DEFAULT_APPROVAL_REQUEST_TIMEOUT_MS },
    {
      id: params.id,
      command: params.command,
      cwd: params.cwd,
      host: params.host,
      security: params.security,
      ask: params.ask,
      agentId: params.agentId,
      resolvedPath: params.resolvedPath,
      sessionKey: params.sessionKey,
      timeoutMs: DEFAULT_APPROVAL_TIMEOUT_MS,
    },
  );

  const payload =
    decisionResult && typeof decisionResult === "object"
      ? (decisionResult as {
          decision?: unknown;
          resolvedBy?: unknown;
          resolvedByDeviceId?: unknown;
          resolvedByClientId?: unknown;
          approvers?: unknown;
        })
      : {};

  const resolvedBy = normalizeOptionalString(payload.resolvedBy);
  const resolvedByDeviceId = normalizeOptionalString(payload.resolvedByDeviceId);
  const resolvedByClientId = normalizeOptionalString(payload.resolvedByClientId);
  const payloadApprovers = Array.isArray(payload.approvers)
    ? uniqueNonEmpty(payload.approvers as Array<string | null | undefined>)
    : [];
  const primaryApprover = resolvedByClientId ?? resolvedBy;
  return {
    decision: normalizeDecision(payload.decision),
    resolvedBy,
    resolvedByDeviceId,
    resolvedByClientId,
    approvers: payloadApprovers.length > 0 ? payloadApprovers : uniqueNonEmpty([primaryApprover]),
  };
}
