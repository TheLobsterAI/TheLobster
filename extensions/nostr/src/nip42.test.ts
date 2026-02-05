/**
 * Tests for NIP-42 authentication
 */

import { describe, it, expect, beforeEach } from "vitest";
import { getPublicKey, verifyEvent } from "nostr-tools";
import {
  createAuthEvent,
  parseAuthChallenge,
  createAuthMessage,
  createAuthHandler,
  isAuthChallenge,
  isAuthOk,
  parseOkResponse,
} from "./nip42.js";

// Test private key
const TEST_SK_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_SK_BYTES = new Uint8Array(32);
for (let i = 0; i < 32; i++) {
  TEST_SK_BYTES[i] = parseInt(TEST_SK_HEX.slice(i * 2, i * 2 + 2), 16);
}
const TEST_PK = getPublicKey(TEST_SK_BYTES);

describe("createAuthEvent", () => {
  const challenge = "test-challenge-string-12345";
  const relayUrl = "wss://relay.example.com";

  it("creates a kind:22242 event", () => {
    const { event, eventId } = createAuthEvent(challenge, relayUrl, TEST_SK_BYTES);
    
    expect(event.kind).toBe(22242);
    expect(eventId).toBe(event.id);
    expect(eventId).toHaveLength(64);
  });

  it("includes relay tag", () => {
    const { event } = createAuthEvent(challenge, relayUrl, TEST_SK_BYTES);
    
    const relayTag = event.tags.find(t => t[0] === "relay");
    expect(relayTag).toBeDefined();
    expect(relayTag?.[1]).toBe(relayUrl);
  });

  it("includes challenge tag", () => {
    const { event } = createAuthEvent(challenge, relayUrl, TEST_SK_BYTES);
    
    const challengeTag = event.tags.find(t => t[0] === "challenge");
    expect(challengeTag).toBeDefined();
    expect(challengeTag?.[1]).toBe(challenge);
  });

  it("has empty content", () => {
    const { event } = createAuthEvent(challenge, relayUrl, TEST_SK_BYTES);
    expect(event.content).toBe("");
  });

  it("is signed by the private key", () => {
    const { event } = createAuthEvent(challenge, relayUrl, TEST_SK_BYTES);
    expect(event.pubkey).toBe(TEST_PK);
  });

  it("produces a valid signature", () => {
    const { event } = createAuthEvent(challenge, relayUrl, TEST_SK_BYTES);
    expect(verifyEvent(event)).toBe(true);
  });

  it("has recent timestamp", () => {
    const before = Math.floor(Date.now() / 1000);
    const { event } = createAuthEvent(challenge, relayUrl, TEST_SK_BYTES);
    const after = Math.floor(Date.now() / 1000);
    
    expect(event.created_at).toBeGreaterThanOrEqual(before);
    expect(event.created_at).toBeLessThanOrEqual(after);
  });
});

describe("parseAuthChallenge", () => {
  const relayUrl = "wss://relay.example.com";

  it("parses valid AUTH message", () => {
    const message = ["AUTH", "challenge-string-123"];
    const result = parseAuthChallenge(message, relayUrl);
    
    expect(result).not.toBeNull();
    expect(result?.relay).toBe(relayUrl);
    expect(result?.challenge).toBe("challenge-string-123");
  });

  it("returns null for non-AUTH messages", () => {
    expect(parseAuthChallenge(["EVENT", {}], relayUrl)).toBeNull();
    expect(parseAuthChallenge(["OK", "id", true], relayUrl)).toBeNull();
    expect(parseAuthChallenge(["NOTICE", "message"], relayUrl)).toBeNull();
  });

  it("returns null for invalid AUTH format", () => {
    expect(parseAuthChallenge(["AUTH"], relayUrl)).toBeNull();
    expect(parseAuthChallenge(["AUTH", ""], relayUrl)).toBeNull();
    expect(parseAuthChallenge(["AUTH", 123], relayUrl)).toBeNull();
    expect(parseAuthChallenge(["AUTH", null], relayUrl)).toBeNull();
  });

  it("returns null for non-array input", () => {
    expect(parseAuthChallenge("AUTH" as any, relayUrl)).toBeNull();
    expect(parseAuthChallenge({} as any, relayUrl)).toBeNull();
    expect(parseAuthChallenge(null as any, relayUrl)).toBeNull();
  });
});

describe("createAuthMessage", () => {
  it("creates AUTH message array", () => {
    const { event } = createAuthEvent("challenge", "wss://relay.test", TEST_SK_BYTES);
    const message = createAuthMessage(event);
    
    expect(Array.isArray(message)).toBe(true);
    expect(message[0]).toBe("AUTH");
    expect(message[1]).toBe(event);
  });
});

describe("createAuthHandler", () => {
  let handler: ReturnType<typeof createAuthHandler>;

  beforeEach(() => {
    handler = createAuthHandler(TEST_SK_BYTES);
  });

  describe("handleChallenge", () => {
    it("creates auth response", () => {
      const response = handler.handleChallenge("test-challenge", "wss://relay.test");
      
      expect(response.event.kind).toBe(22242);
      expect(response.eventId).toHaveLength(64);
    });

    it("marks relay as requiring auth", () => {
      expect(handler.requiresAuth("wss://relay.test")).toBe(false);
      
      handler.handleChallenge("challenge", "wss://relay.test");
      
      expect(handler.requiresAuth("wss://relay.test")).toBe(true);
    });
  });

  describe("markAuthenticated / isAuthenticated", () => {
    it("tracks authenticated relays", () => {
      expect(handler.isAuthenticated("wss://relay.test")).toBe(false);
      
      handler.markAuthenticated("wss://relay.test");
      
      expect(handler.isAuthenticated("wss://relay.test")).toBe(true);
    });

    it("handles multiple relays", () => {
      handler.markAuthenticated("wss://relay1.test");
      handler.markAuthenticated("wss://relay2.test");
      
      expect(handler.isAuthenticated("wss://relay1.test")).toBe(true);
      expect(handler.isAuthenticated("wss://relay2.test")).toBe(true);
      expect(handler.isAuthenticated("wss://relay3.test")).toBe(false);
    });
  });
});

describe("isAuthChallenge", () => {
  it("identifies AUTH challenges", () => {
    expect(isAuthChallenge(["AUTH", "challenge"])).toBe(true);
    expect(isAuthChallenge(["AUTH", "any-string"])).toBe(true);
  });

  it("rejects non-AUTH messages", () => {
    expect(isAuthChallenge(["EVENT", {}])).toBe(false);
    expect(isAuthChallenge(["OK", "id", true])).toBe(false);
    expect(isAuthChallenge(["NOTICE", "msg"])).toBe(false);
  });

  it("rejects malformed AUTH", () => {
    expect(isAuthChallenge(["AUTH"])).toBe(false);
    expect(isAuthChallenge(["AUTH", 123])).toBe(false);
    expect(isAuthChallenge(["AUTH", null])).toBe(false);
  });
});

describe("isAuthOk", () => {
  it("identifies OK responses", () => {
    expect(isAuthOk(["OK", "event-id", true])).toBe(true);
    expect(isAuthOk(["OK", "event-id", false])).toBe(true);
    expect(isAuthOk(["OK", "event-id", true, "message"])).toBe(true);
  });

  it("rejects non-OK messages", () => {
    expect(isAuthOk(["AUTH", "challenge"])).toBe(false);
    expect(isAuthOk(["EVENT", {}])).toBe(false);
    expect(isAuthOk(["NOTICE", "msg"])).toBe(false);
  });

  it("rejects malformed OK", () => {
    expect(isAuthOk(["OK"])).toBe(false);
    expect(isAuthOk(["OK", "id"])).toBe(false);
    expect(isAuthOk(["OK", "id", "string"])).toBe(false);
  });
});

describe("parseOkResponse", () => {
  it("parses successful OK", () => {
    const result = parseOkResponse(["OK", "event-123", true, "success"]);
    
    expect(result).not.toBeNull();
    expect(result?.eventId).toBe("event-123");
    expect(result?.success).toBe(true);
    expect(result?.message).toBe("success");
  });

  it("parses failed OK", () => {
    const result = parseOkResponse(["OK", "event-456", false, "auth-required: need AUTH"]);
    
    expect(result).not.toBeNull();
    expect(result?.eventId).toBe("event-456");
    expect(result?.success).toBe(false);
    expect(result?.message).toBe("auth-required: need AUTH");
  });

  it("handles missing message", () => {
    const result = parseOkResponse(["OK", "event-789", true]);
    
    expect(result).not.toBeNull();
    expect(result?.message).toBe("");
  });

  it("returns null for invalid input", () => {
    expect(parseOkResponse(["AUTH", "challenge"])).toBeNull();
    expect(parseOkResponse(["OK", "id"])).toBeNull();
  });
});
