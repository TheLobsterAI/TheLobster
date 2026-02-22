import { Command } from "commander";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createCliRuntimeCapture } from "./test-runtime-capture.js";

const loadConfig = vi.fn();
const exportTrustAuditEventsToSiem = vi.fn();
const simulateTrustPolicyAgainstAudit = vi.fn();
const readFile = vi.fn();

const { runtimeLogs, runtimeErrors, defaultRuntime, resetRuntimeCapture } =
  createCliRuntimeCapture();

vi.mock("../config/config.js", async () => {
  const actual = await vi.importActual<typeof import("../config/config.js")>("../config/config.js");
  return {
    ...actual,
    loadConfig,
  };
});

vi.mock("../trust/compliance.js", () => ({
  exportTrustAuditEventsToSiem,
  simulateTrustPolicyAgainstAudit,
}));

vi.mock("node:fs/promises", () => ({
  default: { readFile },
  readFile,
}));

vi.mock("../runtime.js", () => ({
  defaultRuntime,
}));

const { registerSecurityCli } = await import("./security-cli.js");

describe("security-cli trust commands", () => {
  async function runCli(args: string[]) {
    const program = new Command();
    registerSecurityCli(program);
    try {
      await program.parseAsync(args, { from: "user" });
    } catch (err) {
      if (!(err instanceof Error && err.message.startsWith("__exit__:"))) {
        throw err;
      }
    }
  }

  beforeEach(() => {
    vi.clearAllMocks();
    resetRuntimeCapture();
    loadConfig.mockReturnValue({});
  });

  it("runs security trust export and prints JSON summary", async () => {
    exportTrustAuditEventsToSiem.mockResolvedValue({
      records: [{ id: 1 }],
      serialized: '{"id":1}\n',
      format: "jsonl",
      outputPath: "/tmp/trust.jsonl",
      verification: { valid: true },
    });

    await runCli(["security", "trust", "export", "--json"]);

    expect(exportTrustAuditEventsToSiem).toHaveBeenCalledWith(
      expect.objectContaining({
        cfg: {},
        format: "jsonl",
      }),
    );
    expect(runtimeLogs[0]).toContain('"ok": true');
    expect(runtimeErrors).toHaveLength(0);
  });

  it("runs security trust simulate and forwards parsed policy patch", async () => {
    readFile.mockResolvedValue(
      JSON.stringify({
        layers: {
          runtime: [
            { id: "deny-exec", effect: "deny", reason: "test", match: { operations: ["exec"] } },
          ],
        },
      }),
    );
    simulateTrustPolicyAgainstAudit.mockResolvedValue({
      totalEvents: 2,
      replayedEvents: 2,
      skippedEvents: 0,
      unchangedEvents: 1,
      changedEvents: 1,
      changeRate: 0.5,
      changes: [],
      posture: {
        current: { score: 80, signals: {} },
        candidate: { score: 75, signals: {} },
        drift: ["denyByDefault"],
      },
    });

    await runCli(["security", "trust", "simulate", "--policy-file", "/tmp/policy.json", "--json"]);

    expect(readFile).toHaveBeenCalledWith("/tmp/policy.json", "utf-8");
    expect(simulateTrustPolicyAgainstAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        cfg: {},
        candidateTrustConfig: expect.objectContaining({
          layers: expect.any(Object),
        }),
      }),
    );
    expect(runtimeLogs[0]).toContain('"changedEvents": 1');
    expect(runtimeErrors).toHaveLength(0);
  });
});
