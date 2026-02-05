# @openclaw/nostr

Nostr DM channel plugin for OpenClaw using **NIP-17 gift-wrapped messages** (default) or NIP-04 encrypted DMs (legacy).

## Overview

This extension adds Nostr as a messaging channel to OpenClaw. It enables your bot to:

- Receive encrypted DMs from Nostr users
- Send encrypted responses back
- Work with NIP-17 compatible clients (0xchat, Amethyst, Damus, Primal, etc.)
- Automatically discover recipient's preferred relays (NIP-65)

## What's New in v2

- **NIP-17 by default** — Gift-wrapped messages hide sender/recipient from relays
- **NIP-65 relay discovery** — Finds recipient's preferred relays before sending
- **Backwards compatible** — Set `dmProtocol: "nip04"` if you need legacy support

## Installation

```bash
openclaw plugins install @openclaw/nostr
```

## Quick Setup

1. Generate a Nostr keypair (if you don't have one):

   ```bash
   # Using nak CLI
   nak key generate
   ```

2. Add to your config:

   ```yaml
   channels:
     nostr:
       privateKey: "${NOSTR_PRIVATE_KEY}"
       relays:
         - wss://relay.damus.io
         - wss://nos.lol
   ```

3. Set the environment variable:

   ```bash
   export NOSTR_PRIVATE_KEY="nsec1..."  # or hex format
   ```

4. Restart the gateway

## Configuration

| Key          | Type     | Default                                     | Description                                                |
| ------------ | -------- | ------------------------------------------- | ---------------------------------------------------------- |
| `privateKey` | string   | required                                    | Bot's private key (nsec or hex format)                     |
| `relays`     | string[] | `["wss://relay.damus.io", "wss://nos.lol"]` | WebSocket relay URLs                                       |
| `dmProtocol` | string   | `"nip17"`                                   | `"nip17"` (gift-wrapped) or `"nip04"` (legacy)             |
| `dmPolicy`   | string   | `"pairing"`                                 | Access control: `pairing`, `allowlist`, `open`, `disabled` |
| `allowFrom`  | string[] | `[]`                                        | Allowed sender pubkeys (npub or hex)                       |
| `enabled`    | boolean  | `true`                                      | Enable/disable the channel                                 |
| `name`       | string   | -                                           | Display name for the account                               |

## DM Protocols

### NIP-17 (Default, Recommended)

Gift-wrapped messages provide metadata privacy:
- Sender and recipient pubkeys hidden from relays
- Forward secrecy with ephemeral keys
- Supported by modern clients (0xchat, Amethyst, Damus, Primal)

### NIP-04 (Legacy)

Use only for backwards compatibility:
- Sender/recipient visible to relays
- Older clients may only support this

```yaml
channels:
  nostr:
    dmProtocol: "nip04"  # Use legacy protocol
```

## NIP-65 Relay Discovery

When sending DMs, the plugin automatically discovers the recipient's preferred relays:

1. **kind:10050** — DM inbox relays (NIP-17 specific)
2. **kind:10002** — General relay list
3. **Fallback** — Your configured relays

This ensures messages are delivered to where the recipient actually reads them.

## Access Control

### DM Policies

- **pairing** (default): Unknown senders receive a pairing code to request access
- **allowlist**: Only pubkeys in `allowFrom` can message the bot
- **open**: Anyone can message the bot (use with caution)
- **disabled**: DMs are disabled

### Example: Allowlist Mode

```yaml
channels:
  nostr:
    privateKey: "${NOSTR_PRIVATE_KEY}"
    dmPolicy: "allowlist"
    allowFrom:
      - "npub1abc..."
      - "0123456789abcdef..."
```

## Migration from v1

If you're upgrading from the NIP-04-only version:

1. **Default behavior changed** — DMs now use NIP-17
2. **Most users**: No action needed (NIP-17 is better)
3. **Legacy clients**: Add `dmProtocol: "nip04"` to keep old behavior

## Protocol Support

| NIP    | Status    | Notes                           |
| ------ | --------- | ------------------------------- |
| NIP-01 | Supported | Basic event structure           |
| NIP-04 | Supported | Legacy encrypted DMs (opt-in)   |
| NIP-17 | Supported | Gift-wrapped DMs (default)      |
| NIP-42 | Planned   | Relay authentication            |
| NIP-65 | Supported | Relay list discovery            |

## Security Notes

- Private keys are never logged
- Event signatures are verified before processing
- Use environment variables for keys, never commit to config files
- NIP-17 hides metadata from relays (recommended)
- Consider using `allowlist` mode in production

## Troubleshooting

### Bot not receiving messages

1. Verify private key is correctly configured
2. Check relay connectivity
3. Ensure `enabled` is not set to `false`
4. Check the bot's public key matches what you're sending to
5. If using NIP-17, ensure the sender's client supports it

### Messages not being delivered

1. Check relay URLs are correct (must use `wss://`)
2. Verify relays are online and accepting connections
3. NIP-65 will try to find recipient's preferred relays
4. Check for rate limiting (reduce message frequency)

### Legacy client compatibility

If the recipient uses an old client:
```yaml
channels:
  nostr:
    dmProtocol: "nip04"
```

## License

MIT
