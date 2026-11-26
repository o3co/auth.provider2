import { authMethods } from "@mod/clients";
import { defineModule } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { serve } from "../../../test/served.ts";

describe("token endpoint", () => {
	it("answers credentials a method finds malformed as a malformed request", async () => {
		const half = defineModule({ name: "half", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(authMethods).by(() => ({
				name: "half",
				claimed: (r) => r.form.get("half_id")?.[0],
				malformed: (r) => r.form.has("half_id") !== r.form.has("half_proof"),
				verify: async () => undefined,
			})),
		]);
		const post = await serve([half]);
		const refused = await post({ grant_type: "client_credentials", half_proof: "p" });
		expect([refused.status, refused.body.error, refused.headers.get("www-authenticate")]).toEqual([
			400,
			"invalid_request",
			null,
		]);
	});
});
