import { describe, expect, it } from "vitest";
import { resolveDiscordUserAllowlist } from "./resolve-users.js";

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), { status: 200 });
}

describe("resolveDiscordUserAllowlist", () => {
  it("ignores partial guild entries", async () => {
    const fetcher = async (url: string) => {
      if (url.endsWith("/users/@me/guilds")) {
        return jsonResponse([
          { id: "g1", name: "Guild One" },
          { id: "g2" },
          { name: "Missing ID" },
        ]);
      }
      if (url.includes("/guilds/g1/members/search")) {
        return jsonResponse([
          {
            user: {
              id: "u1",
              username: "alex",
            },
          },
        ]);
      }
      return new Response("not found", { status: 404 });
    };

    const res = await resolveDiscordUserAllowlist({
      token: "test",
      entries: ["Guild One/alex"],
      fetcher,
    });

    expect(res[0]?.resolved).toBe(true);
    expect(res[0]?.id).toBe("u1");
    expect(res[0]?.guildId).toBe("g1");
  });
});
