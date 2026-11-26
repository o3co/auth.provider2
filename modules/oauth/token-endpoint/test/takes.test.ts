import { auditStandIn } from "@mod/audit/testing";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { expect, it } from "vitest";
import { endpointConfig, endpointModules } from "./deployment.ts";

const runtime = quietRuntime();

it("takes all it names", async () => {
	const input = {
		modules: endpointModules(rateLimitStandIn, auditStandIn().module),
		config: endpointConfig({ issuer: "https://issuer.example" }),
		runtime,
	};
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(input))["token-endpoint"]).toBeUndefined();
});
