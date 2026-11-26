import { authMethods } from "@mod/clients";
import { grants } from "@mod/grants";
import { defineModule } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { answered, logged as book } from "../../../test/deployment.ts";
import { client, serve } from "../../../test/served.ts";

describe("token endpoint", () => {
	it("records the client's assertion as evidence where its method authenticates by one", async () => {
		const asserting = defineModule({ name: "asserting", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(authMethods).by(() => ({
				name: "asserting",
				assertion: true,
				signingAlgorithms: ["ES256"],
				claimed: (r) => (r.form.has("client_assertion") ? "asserted" : undefined),
				verify: async () => ({}),
			})),
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async (input) => answered(input, {}),
			})),
		]);
		const asserted = client("asserted", "asserting", { grants: ["urn:test:echo"] });
		const post = await serve([asserting], { clients: [asserted] });
		const before = book?.sent.length ?? 0;
		expect((await post({ grant_type: "urn:test:echo", client_assertion: "a.b.c" })).status).toBe(
			200,
		);
		const starts = book?.sent.slice(before).filter((s) => s.stage.stage === 1);
		expect(starts?.map((s) => s.stage.preimage.evidence)).toEqual([
			[{ form: "clientAssertion", value: "a.b.c" }],
		]);
	});
});
