import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_APPROVAL_REQUEST_TIMEOUT_MS,
  DEFAULT_APPROVAL_TIMEOUT_MS,
} from "./bash-tools.exec-runtime.js";

vi.mock("./tools/gateway.js", () => ({
  callGatewayTool: vi.fn(),
}));

let callGatewayTool: typeof import("./tools/gateway.js").callGatewayTool;
let requestExecApprovalDecision: typeof import("./bash-tools.exec-approval-request.js").requestExecApprovalDecision;

describe("requestExecApprovalDecision", () => {
  beforeAll(async () => {
    ({ callGatewayTool } = await import("./tools/gateway.js"));
    ({ requestExecApprovalDecision } = await import("./bash-tools.exec-approval-request.js"));
  });

  beforeEach(() => {
    vi.mocked(callGatewayTool).mockClear();
  });

  it("returns string decisions", async () => {
    vi.mocked(callGatewayTool).mockResolvedValue({
      decision: "allow-once",
      resolvedBy: "Operator",
      resolvedByDeviceId: "device-1",
      resolvedByClientId: "client-1",
    });

    const result = await requestExecApprovalDecision({
      id: "approval-id",
      command: "echo hi",
      cwd: "/tmp",
      host: "gateway",
      security: "allowlist",
      ask: "always",
      agentId: "main",
      resolvedPath: "/usr/bin/echo",
      sessionKey: "session",
    });

    expect(result).toEqual({
      decision: "allow-once",
      resolvedBy: "Operator",
      resolvedByDeviceId: "device-1",
      resolvedByClientId: "client-1",
      approvers: ["client-1"],
    });
    expect(callGatewayTool).toHaveBeenCalledWith(
      "exec.approval.request",
      { timeoutMs: DEFAULT_APPROVAL_REQUEST_TIMEOUT_MS },
      {
        id: "approval-id",
        command: "echo hi",
        cwd: "/tmp",
        host: "gateway",
        security: "allowlist",
        ask: "always",
        agentId: "main",
        resolvedPath: "/usr/bin/echo",
        sessionKey: "session",
        timeoutMs: DEFAULT_APPROVAL_TIMEOUT_MS,
      },
    );
  });

  it("returns null for missing or non-string decisions", async () => {
    vi.mocked(callGatewayTool).mockResolvedValueOnce({});
    await expect(
      requestExecApprovalDecision({
        id: "approval-id",
        command: "echo hi",
        cwd: "/tmp",
        host: "node",
        security: "allowlist",
        ask: "on-miss",
      }),
    ).resolves.toEqual({
      decision: null,
      resolvedBy: null,
      resolvedByDeviceId: null,
      resolvedByClientId: null,
      approvers: [],
    });

    vi.mocked(callGatewayTool).mockResolvedValueOnce({ decision: 123 });
    await expect(
      requestExecApprovalDecision({
        id: "approval-id-2",
        command: "echo hi",
        cwd: "/tmp",
        host: "node",
        security: "allowlist",
        ask: "on-miss",
      }),
    ).resolves.toEqual({
      decision: null,
      resolvedBy: null,
      resolvedByDeviceId: null,
      resolvedByClientId: null,
      approvers: [],
    });
  });

  it("normalizes approver metadata", async () => {
    vi.mocked(callGatewayTool).mockResolvedValue({
      decision: "allow-always",
      resolvedBy: "  operator-1  ",
      resolvedByDeviceId: "Device-1",
      resolvedByClientId: "client-1",
    });

    await expect(
      requestExecApprovalDecision({
        id: "approval-id-3",
        command: "echo hi",
        cwd: "/tmp",
        host: "node",
        security: "allowlist",
        ask: "on-miss",
      }),
    ).resolves.toEqual({
      decision: "allow-always",
      resolvedBy: "operator-1",
      resolvedByDeviceId: "Device-1",
      resolvedByClientId: "client-1",
      approvers: ["client-1"],
    });
  });

  it("prefers explicit approver principals from payload", async () => {
    vi.mocked(callGatewayTool).mockResolvedValue({
      decision: "allow-once",
      resolvedBy: "Operator",
      resolvedByClientId: "client-1",
      approvers: ["approver-a", " approver-b ", "APPROVER-A", ""],
    });

    await expect(
      requestExecApprovalDecision({
        id: "approval-id-4",
        command: "echo hi",
        cwd: "/tmp",
        host: "gateway",
        security: "allowlist",
        ask: "always",
      }),
    ).resolves.toEqual({
      decision: "allow-once",
      resolvedBy: "Operator",
      resolvedByDeviceId: null,
      resolvedByClientId: "client-1",
      approvers: ["approver-a", "approver-b"],
    });
  });
});
