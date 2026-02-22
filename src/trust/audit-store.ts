import fs from "node:fs/promises";
import path from "node:path";
import type { OpenClawConfig } from "../config/config.js";
import { resolveStateDir } from "../config/paths.js";
import { expandHomePrefix } from "../infra/home-dir.js";
import {
  createTrustAuditEvent,
  verifyTrustAuditChain,
  type TrustAuditEvent,
  type TrustAuditEventKind,
} from "./trust-plane.js";

const TRUST_AUDIT_DEFAULT_FILE = "trust/trust-audit.jsonl";

const pathLocks = new Map<string, Promise<void>>();
const lastHashByPath = new Map<string, string | null>();

function resolveAuditPath(params: { cfg?: OpenClawConfig; overridePath?: string }): string {
  const configured = params.overridePath?.trim() || params.cfg?.trust?.audit?.path?.trim();
  if (configured) {
    return path.resolve(expandHomePrefix(configured));
  }
  const stateDir = resolveStateDir(process.env);
  return path.join(stateDir, TRUST_AUDIT_DEFAULT_FILE);
}

async function withPathLock<T>(filePath: string, fn: () => Promise<T>): Promise<T> {
  const previous = pathLocks.get(filePath) ?? Promise.resolve();
  let releaseLock: (() => void) | undefined;
  const current = new Promise<void>((resolve) => {
    releaseLock = resolve;
  });
  pathLocks.set(
    filePath,
    previous.catch(() => undefined).then(() => current),
  );

  await previous.catch(() => undefined);
  try {
    return await fn();
  } finally {
    releaseLock?.();
    const active = pathLocks.get(filePath);
    if (active === current) {
      pathLocks.delete(filePath);
    }
  }
}

async function readLastHash(filePath: string): Promise<string | null> {
  if (lastHashByPath.has(filePath)) {
    return lastHashByPath.get(filePath) ?? null;
  }

  const raw = await fs.readFile(filePath, "utf8").catch((err: unknown) => {
    if ((err as NodeJS.ErrnoException)?.code === "ENOENT") {
      return "";
    }
    throw err;
  });

  const lines = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const lastLine = lines.at(-1);
  if (!lastLine) {
    lastHashByPath.set(filePath, null);
    return null;
  }

  let parsed: { hash?: unknown } | null = null;
  try {
    parsed = JSON.parse(lastLine) as { hash?: unknown };
  } catch {
    throw new Error(`Trust audit log is corrupted: cannot parse last JSONL entry at ${filePath}`);
  }

  const hash = typeof parsed?.hash === "string" ? parsed.hash : null;
  if (!hash) {
    throw new Error(`Trust audit log is corrupted: missing hash on last entry at ${filePath}`);
  }
  lastHashByPath.set(filePath, hash);
  return hash;
}

export async function appendTrustAuditEvent(params: {
  cfg?: OpenClawConfig;
  overridePath?: string;
  kind: TrustAuditEventKind;
  tsMs: number;
  tenantId: string;
  actorId: string;
  actionId: string;
  payload: Record<string, unknown>;
}): Promise<TrustAuditEvent> {
  const filePath = resolveAuditPath({ cfg: params.cfg, overridePath: params.overridePath });

  return await withPathLock(filePath, async () => {
    const previousHash = await readLastHash(filePath);
    const event = createTrustAuditEvent({
      id: `${params.kind}-${params.actionId}-${params.tsMs}`,
      kind: params.kind,
      tsMs: params.tsMs,
      tenantId: params.tenantId,
      actorId: params.actorId,
      actionId: params.actionId,
      payload: params.payload,
      previousHash,
    });

    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.appendFile(filePath, `${JSON.stringify(event)}\n`, "utf8");
    lastHashByPath.set(filePath, event.hash);
    return event;
  });
}

export async function readTrustAuditEvents(params: {
  cfg?: OpenClawConfig;
  overridePath?: string;
  limit?: number;
}): Promise<TrustAuditEvent[]> {
  const filePath = resolveAuditPath({ cfg: params.cfg, overridePath: params.overridePath });
  const raw = await fs.readFile(filePath, "utf8").catch((err: unknown) => {
    if ((err as NodeJS.ErrnoException)?.code === "ENOENT") {
      return "";
    }
    throw err;
  });

  const events: TrustAuditEvent[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    const parsed = JSON.parse(trimmed) as TrustAuditEvent;
    events.push(parsed);
  }

  const limit = params.limit;
  if (typeof limit === "number" && limit > 0 && events.length > limit) {
    return events.slice(events.length - limit);
  }
  return events;
}

export async function verifyTrustAuditLog(params: {
  cfg?: OpenClawConfig;
  overridePath?: string;
}): Promise<{ valid: boolean; error?: string; index?: number }> {
  const events = await readTrustAuditEvents({ cfg: params.cfg, overridePath: params.overridePath });
  return verifyTrustAuditChain(events);
}

export function resetTrustAuditStoreForTests() {
  pathLocks.clear();
  lastHashByPath.clear();
}
