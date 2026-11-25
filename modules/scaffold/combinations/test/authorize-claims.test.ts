import { expect, it } from "vitest";

// The decision is authorize-claims' manifest's (opt-in, as authorize, joining it and claims-selection); this holds how it reads.
import { composed, full, optIns } from "../src/contract.ts";

it("comes with authorize and claims-selection alone, never bringing authorize where nothing named it", () => {
	expect(optIns()).toContain("@mod/authorize-claims");
	expect(full()).not.toContain("@mod/authorize");
	expect(full()).not.toContain("@mod/authorize-claims");
	const named = composed({ features: { login: ["@mod/authorize", "@mod/claims-selection"] } });
	expect(named).toContain("@mod/authorize-claims");
});
