import { loadConfig } from "../../config/config.js";
import type { ExecApprovalForwarder } from "../../infra/exec-approval-forwarder.js";
import {
  DEFAULT_EXEC_APPROVAL_TIMEOUT_MS,
  type ExecApprovalDecision,
} from "../../infra/exec-approvals.js";
import {
  buildExecTrustAction,
  recordTrustApprovalEvent,
  resolveTrustRuntimeConfig,
} from "../../trust/runtime.js";
import type { ExecApprovalManager } from "../exec-approval-manager.js";
import {
  ErrorCodes,
  errorShape,
  formatValidationErrors,
  validateExecApprovalRequestParams,
  validateExecApprovalResolveParams,
} from "../protocol/index.js";
import type { GatewayRequestHandlers } from "./types.js";

function normalizeOptionalString(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
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

function resolveApproverPrincipals(params: {
  resolvedByClientId: string | null;
  resolvedBy: string | null;
}): string[] {
  return uniqueNonEmpty([params.resolvedByClientId ?? params.resolvedBy]);
}

export function createExecApprovalHandlers(
  manager: ExecApprovalManager,
  opts?: { forwarder?: ExecApprovalForwarder },
): GatewayRequestHandlers {
  return {
    "exec.approval.request": async ({ params, respond, context, client }) => {
      if (!validateExecApprovalRequestParams(params)) {
        respond(
          false,
          undefined,
          errorShape(
            ErrorCodes.INVALID_REQUEST,
            `invalid exec.approval.request params: ${formatValidationErrors(
              validateExecApprovalRequestParams.errors,
            )}`,
          ),
        );
        return;
      }
      const p = params as {
        id?: string;
        command: string;
        cwd?: string;
        host?: string;
        security?: string;
        ask?: string;
        agentId?: string;
        resolvedPath?: string;
        sessionKey?: string;
        timeoutMs?: number;
        twoPhase?: boolean;
      };
      const twoPhase = p.twoPhase === true;
      const timeoutMs =
        typeof p.timeoutMs === "number" ? p.timeoutMs : DEFAULT_EXEC_APPROVAL_TIMEOUT_MS;
      const explicitId = typeof p.id === "string" && p.id.trim().length > 0 ? p.id.trim() : null;
      if (explicitId && manager.getSnapshot(explicitId)) {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, "approval id already pending"),
        );
        return;
      }
      const request = {
        command: p.command,
        cwd: p.cwd ?? null,
        host: p.host ?? null,
        security: p.security ?? null,
        ask: p.ask ?? null,
        agentId: p.agentId ?? null,
        resolvedPath: p.resolvedPath ?? null,
        sessionKey: p.sessionKey ?? null,
      };
      const record = manager.create(request, timeoutMs, explicitId);
      record.requestedByConnId = client?.connId ?? null;
      record.requestedByDeviceId = client?.connect?.device?.id ?? null;
      record.requestedByClientId = client?.connect?.client?.id ?? null;
      // Use register() to synchronously add to pending map before sending any response.
      // This ensures the approval ID is valid immediately after the "accepted" response.
      let decisionPromise: Promise<
        import("../../infra/exec-approvals.js").ExecApprovalDecision | null
      >;
      try {
        decisionPromise = manager.register(record, timeoutMs);
      } catch (err) {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, `registration failed: ${String(err)}`),
        );
        return;
      }
      context.broadcast(
        "exec.approval.requested",
        {
          id: record.id,
          request: record.request,
          createdAtMs: record.createdAtMs,
          expiresAtMs: record.expiresAtMs,
        },
        { dropIfSlow: true },
      );
      void opts?.forwarder
        ?.handleRequested({
          id: record.id,
          request: record.request,
          createdAtMs: record.createdAtMs,
          expiresAtMs: record.expiresAtMs,
        })
        .catch((err) => {
          context.logGateway?.error?.(`exec approvals: forward request failed: ${String(err)}`);
        });

      // Only send immediate "accepted" response when twoPhase is requested.
      // This preserves single-response semantics for existing callers.
      if (twoPhase) {
        respond(
          true,
          {
            status: "accepted",
            id: record.id,
            createdAtMs: record.createdAtMs,
            expiresAtMs: record.expiresAtMs,
          },
          undefined,
        );
      }

      const decision = await decisionPromise;
      const resolved = manager.getSnapshot(record.id);
      const resolvedBy = resolved?.resolvedBy ?? null;
      const resolvedByDeviceId = resolved?.resolvedByDeviceId ?? null;
      const resolvedByClientId = resolved?.resolvedByClientId ?? null;
      // Send final response with decision for callers using expectFinal:true.
      respond(
        true,
        {
          id: record.id,
          decision,
          createdAtMs: record.createdAtMs,
          expiresAtMs: record.expiresAtMs,
          resolvedBy,
          resolvedByDeviceId,
          resolvedByClientId,
          approvers: resolveApproverPrincipals({ resolvedByClientId, resolvedBy }),
        },
        undefined,
      );
    },
    "exec.approval.waitDecision": async ({ params, respond }) => {
      const p = params as { id?: string };
      const id = typeof p.id === "string" ? p.id.trim() : "";
      if (!id) {
        respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "id is required"));
        return;
      }
      const decisionPromise = manager.awaitDecision(id);
      if (!decisionPromise) {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, "approval expired or not found"),
        );
        return;
      }
      // Capture snapshot before await (entry may be deleted after grace period)
      const snapshot = manager.getSnapshot(id);
      const decision = await decisionPromise;
      const resolvedBy = snapshot?.resolvedBy ?? null;
      const resolvedByDeviceId = snapshot?.resolvedByDeviceId ?? null;
      const resolvedByClientId = snapshot?.resolvedByClientId ?? null;
      // Return decision (can be null on timeout) - let clients handle via askFallback
      respond(
        true,
        {
          id,
          decision,
          createdAtMs: snapshot?.createdAtMs,
          expiresAtMs: snapshot?.expiresAtMs,
          resolvedBy,
          resolvedByDeviceId,
          resolvedByClientId,
          approvers: resolveApproverPrincipals({ resolvedByClientId, resolvedBy }),
        },
        undefined,
      );
    },
    "exec.approval.resolve": async ({ params, respond, client, context }) => {
      if (!validateExecApprovalResolveParams(params)) {
        respond(
          false,
          undefined,
          errorShape(
            ErrorCodes.INVALID_REQUEST,
            `invalid exec.approval.resolve params: ${formatValidationErrors(
              validateExecApprovalResolveParams.errors,
            )}`,
          ),
        );
        return;
      }
      const p = params as { id: string; decision: string };
      const decision = p.decision as ExecApprovalDecision;
      if (decision !== "allow-once" && decision !== "allow-always" && decision !== "deny") {
        respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "invalid decision"));
        return;
      }
      const resolvedBy =
        normalizeOptionalString(client?.connect?.client?.displayName) ??
        normalizeOptionalString(client?.connect?.client?.id);
      const resolvedByDeviceId = normalizeOptionalString(client?.connect?.device?.id);
      const resolvedByClientId = normalizeOptionalString(client?.connect?.client?.id);
      const ok = manager.resolve(p.id, decision, {
        resolvedBy,
        resolvedByDeviceId,
        resolvedByClientId,
      });
      if (!ok) {
        respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "unknown approval id"));
        return;
      }
      const snapshot = manager.getSnapshot(p.id);
      const approvers = resolveApproverPrincipals({ resolvedByClientId, resolvedBy });
      if (snapshot) {
        try {
          const cfg = loadConfig();
          const runtime = resolveTrustRuntimeConfig({ cfg, trustConfig: cfg.trust });
          const action = buildExecTrustAction({
            runtime,
            command: snapshot.request.command,
            stage: "proposal",
            host: snapshot.request.host === "node" ? "node" : "gateway",
            workdir: snapshot.request.cwd?.trim() || process.cwd(),
            actorId:
              snapshot.request.agentId?.trim() ||
              snapshot.request.sessionKey?.trim() ||
              snapshot.requestedByDeviceId ||
              snapshot.requestedByClientId ||
              p.id,
            actorType: snapshot.request.sessionKey ? "human" : "agent",
            sessionId: snapshot.request.sessionKey?.trim() || snapshot.requestedByClientId || p.id,
            channel: "gateway-rpc",
            audience: "operator",
          });
          void recordTrustApprovalEvent({
            cfg,
            trustConfig: cfg.trust,
            action,
            approvalId: p.id,
            decision,
            resolvedBy,
            resolvedByDeviceId,
            resolvedByClientId,
            approvers,
            scope: decision === "allow-always" ? "policy" : "once",
          }).catch((err) => {
            context.logGateway?.error?.(
              `trust: failed to record approval audit event: ${String(err)}`,
            );
          });
        } catch (err) {
          context.logGateway?.warn?.(
            `trust: unable to load config for approval audit event: ${String(err)}`,
          );
        }
      }
      const ts = Date.now();
      context.broadcast(
        "exec.approval.resolved",
        {
          id: p.id,
          decision,
          resolvedBy,
          resolvedByDeviceId,
          resolvedByClientId,
          approvers,
          ts,
        },
        { dropIfSlow: true },
      );
      void opts?.forwarder
        ?.handleResolved({
          id: p.id,
          decision,
          resolvedBy,
          resolvedByDeviceId,
          resolvedByClientId,
          approvers,
          ts,
        })
        .catch((err) => {
          context.logGateway?.error?.(`exec approvals: forward resolve failed: ${String(err)}`);
        });
      respond(true, { ok: true }, undefined);
    },
  };
}
