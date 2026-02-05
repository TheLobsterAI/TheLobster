/**
 * NIP-42 Authentication
 * 
 * Handles relay authentication for relays that require it.
 * 
 * Flow:
 * 1. Relay sends AUTH challenge: ["AUTH", "<challenge>"]
 * 2. Client signs kind:22242 event with challenge in tags
 * 3. Client sends: ["AUTH", <signed-event>]
 * 4. Relay verifies and grants access
 * 
 * @see https://github.com/nostr-protocol/nips/blob/master/42.md
 */

import { finalizeEvent, type Event } from "nostr-tools";
import { makeAuthEvent as nostrToolsMakeAuthEvent } from "nostr-tools/nip42";

// ============================================================================
// Types
// ============================================================================

export interface AuthChallenge {
  /** The relay URL that sent the challenge */
  relay: string;
  /** The challenge string from the relay */
  challenge: string;
}

export interface AuthResponse {
  /** The signed authentication event */
  event: Event;
  /** Event ID */
  eventId: string;
}

// ============================================================================
// Auth Event Creation
// ============================================================================

/**
 * Create a NIP-42 authentication event
 * 
 * Uses nostr-tools' implementation for compatibility.
 * 
 * @param challenge - The challenge string from the relay
 * @param relayUrl - The relay URL requesting auth
 * @param privateKeyBytes - User's private key as Uint8Array
 * @returns Signed kind:22242 event
 */
export function createAuthEvent(
  challenge: string,
  relayUrl: string,
  privateKeyBytes: Uint8Array,
): AuthResponse {
  // Use nostr-tools' makeAuthEvent for compatibility
  const event = nostrToolsMakeAuthEvent(relayUrl, challenge);
  
  // Sign the event
  const signedEvent = finalizeEvent(event, privateKeyBytes);

  return {
    event: signedEvent,
    eventId: signedEvent.id,
  };
}

// ============================================================================
// Challenge Parsing
// ============================================================================

/**
 * Parse an AUTH message from a relay
 * 
 * @param message - Raw message from relay (parsed JSON)
 * @param relayUrl - The relay URL
 * @returns AuthChallenge if valid, null otherwise
 */
export function parseAuthChallenge(
  message: unknown[],
  relayUrl: string,
): AuthChallenge | null {
  // AUTH message format: ["AUTH", "<challenge>"]
  if (!Array.isArray(message)) {
    return null;
  }

  if (message[0] !== "AUTH") {
    return null;
  }

  const challenge = message[1];
  if (typeof challenge !== "string" || challenge.length === 0) {
    return null;
  }

  return {
    relay: relayUrl,
    challenge,
  };
}

/**
 * Create the AUTH response message to send to relay
 * 
 * @param event - The signed auth event
 * @returns Message array to send: ["AUTH", <event>]
 */
export function createAuthMessage(event: Event): unknown[] {
  return ["AUTH", event];
}

// ============================================================================
// Auth Handler
// ============================================================================

export interface AuthHandler {
  /** Handle an AUTH challenge from a relay */
  handleChallenge: (challenge: string, relayUrl: string) => AuthResponse;
  /** Check if a relay requires auth (based on past challenges) */
  requiresAuth: (relayUrl: string) => boolean;
  /** Mark a relay as authenticated */
  markAuthenticated: (relayUrl: string) => void;
  /** Check if already authenticated with a relay */
  isAuthenticated: (relayUrl: string) => boolean;
}

/**
 * Create an auth handler for a specific private key
 * 
 * @param privateKeyBytes - User's private key
 * @returns AuthHandler instance
 */
export function createAuthHandler(privateKeyBytes: Uint8Array): AuthHandler {
  const challengedRelays = new Set<string>();
  const authenticatedRelays = new Set<string>();

  return {
    handleChallenge(challenge: string, relayUrl: string): AuthResponse {
      challengedRelays.add(relayUrl);
      return createAuthEvent(challenge, relayUrl, privateKeyBytes);
    },

    requiresAuth(relayUrl: string): boolean {
      return challengedRelays.has(relayUrl);
    },

    markAuthenticated(relayUrl: string): void {
      authenticatedRelays.add(relayUrl);
    },

    isAuthenticated(relayUrl: string): boolean {
      return authenticatedRelays.has(relayUrl);
    },
  };
}

// ============================================================================
// Relay Message Types
// ============================================================================

/**
 * Check if a relay message is an AUTH challenge
 */
export function isAuthChallenge(message: unknown[]): boolean {
  return Array.isArray(message) && message[0] === "AUTH" && typeof message[1] === "string";
}

/**
 * Check if a relay message is an OK response to AUTH
 */
export function isAuthOk(message: unknown[]): boolean {
  // OK format: ["OK", "<event-id>", true/false, "<message>"]
  return (
    Array.isArray(message) &&
    message[0] === "OK" &&
    typeof message[1] === "string" &&
    typeof message[2] === "boolean"
  );
}

/**
 * Parse an OK response
 */
export function parseOkResponse(message: unknown[]): {
  eventId: string;
  success: boolean;
  message: string;
} | null {
  if (!isAuthOk(message)) {
    return null;
  }

  return {
    eventId: message[1] as string,
    success: message[2] as boolean,
    message: (message[3] as string) ?? "",
  };
}
