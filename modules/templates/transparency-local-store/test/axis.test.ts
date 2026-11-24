import { composed } from "@mod/combinations";
import { expect, it } from "vitest";

it("comes with transparency-local only where a composition names it for transparency's axis, never as its default", () => {
	const features = { keys: ["@mod/passkeys"] };
	const unnamed = composed({ features });
	expect(unnamed).toContain("@mod/transparency");
	expect(unnamed).not.toContain("@mod/transparency-local");
	const named = composed({ features, axes: { "@mod/transparency": "@mod/transparency-local" } });
	expect(named).toContain("@mod/transparency-local");
	expect(named).toContain("@mod/transparency-local-store");
});
