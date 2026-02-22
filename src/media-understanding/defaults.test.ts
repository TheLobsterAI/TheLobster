import { describe, expect, it } from "vitest";
import { DEFAULT_AUDIO_MODELS } from "./defaults.js";

describe("DEFAULT_AUDIO_MODELS", () => {
  it("includes Mistral Voxtral default", () => {
    expect(DEFAULT_AUDIO_MODELS.mistral).toBe("voxtral-mini-latest");
  });
});
