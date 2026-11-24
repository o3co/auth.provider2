import { expect, it } from "vitest";

// The decision is passkey-reset's manifest's (opt-in, joining nothing); this holds how it reads.
import { composed, full, optIns } from "../src/contract.ts";

it("comes only where a composition names it, as the reset's path is a power the embedder chooses", () => {
	expect(optIns()).toContain("@mod/passkey-reset");
	expect(composed({ features: { keys: ["@mod/passkeys"] } })).not.toContain("@mod/passkey-reset");
	expect(full()).not.toContain("@mod/passkey-reset");
});

it("brings what it needs to run where named: transparency and passkeys", () => {
	const named = composed({ features: { recovery: ["@mod/passkey-reset"] } });
	expect(named).toContain("@mod/passkey-reset");
	expect(named).toContain("@mod/passkeys");
	expect(named).toContain("@mod/transparency");
});
