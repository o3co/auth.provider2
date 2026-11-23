import { expect, it } from "vitest";
import { liveness } from "../src/liveness.ts";
import { readyz } from "../src/readiness.ts";

it("serves its liveness and readiness on a probe listener, where a server has one", () => {
	expect(liveness().exposure).toBe("probe");
	expect(
		readyz(async () => ({ answer: "ready", report: { ready: true, probes: [] } }) as never)
			.exposure,
	).toBe("probe");
});
