import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { appendTrustAuditEvent, resetTrustAuditStoreForTests } from "./audit-store.js";
import { exportTrustAuditEventsToSiem, simulateTrustPolicyAgainstAudit } from "./compliance.js";

async function makeTempAuditPath() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-trust-compliance-"));
  return {
    dir,
    file: path.join(dir, "trust-audit.jsonl"),
  };
}

afterEach(() => {
  resetTrustAuditStoreForTests();
});

describe("trust compliance", () => {
  it("exports SIEM records and redacts payload snippets by default", async () => {
    const temp = await makeTempAuditPath();
    await appendTrustAuditEvent({
      overridePath: temp.file,
      kind: "delivery",
      tsMs: Date.now(),
      tenantId: "tenant-test",
      actorId: "actor-test",
      actionId: "action-1",
      payload: {
        stage: "outbound",
        operation: "send",
        intent: "message:send",
        risk: "high",
        decision: "deny",
        reason: "blocked",
        source: { system: "chat", resource: "slack", dataClass: "internal" },
        destination: { kind: "chat", target: "channel:C123", dataClass: "internal" },
        textPayload: "secret text",
        filePayloads: ["secret-file"],
      },
    });

    const exported = await exportTrustAuditEventsToSiem({
      auditPath: temp.file,
      format: "jsonl",
      verifyChain: true,
    });

    expect(exported.records.length).toBe(1);
    expect(exported.verification?.valid).toBe(true);
    const payload = exported.records[0]?.["payload"] as Record<string, unknown> | undefined;
    expect(payload?.textPayload).toBeUndefined();
    expect(payload?.filePayloads).toBeUndefined();

    const exportedWithPayload = await exportTrustAuditEventsToSiem({
      auditPath: temp.file,
      format: "jsonl",
      includePayload: true,
    });
    const payloadWithSnippets = exportedWithPayload.records[0]?.["payload"] as
      | Record<string, unknown>
      | undefined;
    expect(payloadWithSnippets?.textPayload).toBe("secret text");

    await fs.rm(temp.dir, { recursive: true, force: true });
  });

  it("simulates candidate policy changes against recorded audit events", async () => {
    const temp = await makeTempAuditPath();
    await appendTrustAuditEvent({
      overridePath: temp.file,
      kind: "execution",
      tsMs: Date.now(),
      tenantId: "tenant-test",
      actorId: "actor-test",
      actionId: "action-2",
      payload: {
        stage: "execution",
        operation: "exec",
        intent: "exec:node",
        risk: "high",
        decision: "allow",
        source: { system: "exec", resource: "/tmp", dataClass: "internal" },
        destination: { kind: "tool", target: "exec:node", dataClass: "internal" },
        context: {
          channel: "gateway-rpc",
          audience: "operator",
          sessionId: "session-a",
          policyVersion: "trust-v1",
        },
        approval: {
          required: true,
          satisfied: true,
          dualControlRequired: false,
          grantId: "approval-a",
        },
      },
    });

    const simulation = await simulateTrustPolicyAgainstAudit({
      auditPath: temp.file,
      candidateTrustConfig: {
        layers: {
          runtime: [
            {
              id: "deny-exec",
              effect: "deny",
              reason: "block exec during simulation",
              match: { operations: ["exec"] },
            },
          ],
        },
      },
    });

    expect(simulation.replayedEvents).toBe(1);
    expect(simulation.changedEvents).toBe(1);
    expect(simulation.changes[0]?.from).toBe("allow");
    expect(simulation.changes[0]?.to).toBe("deny");

    await fs.rm(temp.dir, { recursive: true, force: true });
  });
});
