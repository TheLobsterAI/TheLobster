/**
 * NIP-17 Gift Wrap Implementation
 * 
 * Message structure:
 * - Kind 14 (rumor): Unsigned chat message
 * - Kind 13 (seal): Rumor encrypted to recipient, signed by sender
 * - Kind 1059 (gift wrap): Seal encrypted with ephemeral key
 * 
 * Benefits over NIP-04:
 * - Metadata privacy: sender/recipient hidden from relays
 * - Forward secrecy: ephemeral keys for each message
 * 
 * @see https://github.com/nostr-protocol/nips/blob/master/17.md
 */

import { getPublicKey, nip19, nip59, type Event } from "nostr-tools";

// ============================================================================
// Types
// ============================================================================

export interface UnwrappedMessage {
  /** Sender's hex pubkey */
  senderPubkey: string;
  /** Sender's npub */
  senderNpub: string;
  /** Decrypted message content */
  content: string;
  /** Original event timestamp (seconds) */
  createdAt: number;
  /** Gift wrap event ID */
  eventId: string;
}

export interface WrapResult {
  /** The gift wrap event to publish */
  event: Event;
  /** Event ID */
  eventId: string;
}

// ============================================================================
// Gift Wrap
// ============================================================================

/**
 * Create a NIP-17 gift-wrapped message
 * 
 * @param recipientPubkey - Recipient's pubkey (hex or npub)
 * @param content - Message content
 * @param privateKeyBytes - Sender's private key as Uint8Array
 * @returns Gift wrap event ready to publish
 */
export function createGiftWrap(
  recipientPubkey: string,
  content: string,
  privateKeyBytes: Uint8Array,
): WrapResult {
  // Normalize recipient pubkey
  let targetPubkey = recipientPubkey;
  if (recipientPubkey.startsWith("npub")) {
    const decoded = nip19.decode(recipientPubkey);
    targetPubkey = decoded.data as string;
  }

  // Create kind 14 rumor (unsigned chat message)
  const rumor = nip59.createRumor(
    {
      kind: 14,
      content,
      tags: [["p", targetPubkey]],
    },
    privateKeyBytes,
  );

  // Create kind 13 seal (rumor encrypted to recipient, signed by sender)
  const seal = nip59.createSeal(rumor, privateKeyBytes, targetPubkey);

  // Create kind 1059 gift wrap (seal encrypted with ephemeral key)
  const wrap = nip59.createWrap(seal, targetPubkey);

  return {
    event: wrap,
    eventId: wrap.id,
  };
}

/**
 * Unwrap a NIP-17 gift-wrapped message
 * 
 * @param wrapEvent - Kind 1059 gift wrap event
 * @param privateKeyBytes - Recipient's private key as Uint8Array
 * @returns Unwrapped message or null if decryption fails
 */
export function unwrapGiftWrap(
  wrapEvent: Event,
  privateKeyBytes: Uint8Array,
): UnwrappedMessage | null {
  if (wrapEvent.kind !== 1059) {
    return null;
  }

  try {
    // nip59.unwrapEvent handles both layers (gift wrap → seal → rumor)
    const rumor = nip59.unwrapEvent(wrapEvent, privateKeyBytes);

    if (!rumor) {
      return null;
    }

    // Accept kind 14 (NIP-17 chat) or kind 4 (legacy DM in gift wrap)
    if (rumor.kind !== 14 && rumor.kind !== 4) {
      return null;
    }

    const senderPubkey = rumor.pubkey;
    const senderNpub = nip19.npubEncode(senderPubkey);

    return {
      senderPubkey,
      senderNpub,
      content: rumor.content,
      createdAt: rumor.created_at,
      eventId: wrapEvent.id,
    };
  } catch {
    // Decryption failed - not for us or corrupted
    return null;
  }
}

// ============================================================================
// Utilities
// ============================================================================

/**
 * Convert hex string to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Get public key from private key bytes
 */
export function getPublicKeyFromPrivate(privateKeyBytes: Uint8Array): string {
  return getPublicKey(privateKeyBytes);
}

/**
 * Normalize a target identifier to hex pubkey
 */
export function normalizeNostrTarget(target: string): string | null {
  // Already hex pubkey (64 chars)
  if (/^[a-f0-9]{64}$/i.test(target)) {
    return target.toLowerCase();
  }

  // npub format
  if (target.startsWith("npub1")) {
    try {
      const decoded = nip19.decode(target);
      if (decoded.type === "npub") {
        return decoded.data as string;
      }
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Check if a string looks like a Nostr identifier
 */
export function looksLikeNostrId(value: string): boolean {
  // npub format
  if (value.startsWith("npub1") && value.length === 63) {
    return true;
  }

  // hex pubkey
  if (/^[a-f0-9]{64}$/i.test(value)) {
    return true;
  }

  return false;
}
