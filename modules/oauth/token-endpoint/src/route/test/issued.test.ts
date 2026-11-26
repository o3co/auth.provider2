import { grants } from "@mod/grants";
import { defineModule } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { echoClients, events, serve } from "../../../test/served.ts";

describe("token endpoint", () => {
	it("refuses an authentication time far ahead of the clock as invalid_grant, by tokens' own rule", async () => {
		const ahead = defineModule({ name: "ahead", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ client, param, issue }) => {
					const grant = {
						subject: "s",
						subjectKind: "user" as const,
						issuedTo: client.id,
						audience: ["https://api"],
						scope: [],
						authenticatedAt: 1_800_000_000_000 + Number(param("ahead")),
					};
					const issued = await issue({ access: grant });
					return issued.kind === "refused" ? issued : { kind: "issued", body: {} };
				},
			})),
		]);
		const post = await serve([ahead], { clients: [echoClients.echo()] });
		expect((await post({ grant_type: "urn:test:echo", ahead: "300000" }, "echo")).status).toBe(200);
		const refused = await post({ grant_type: "urn:test:echo", ahead: "300001" }, "echo");
		expect([refused.status, refused.body.error]).toEqual([400, "invalid_grant"]);
		expect(events.at(-1)?.attributes).toMatchObject({
			policy: "tokens",
			reason: "issuance_refused",
		});
	});
});
