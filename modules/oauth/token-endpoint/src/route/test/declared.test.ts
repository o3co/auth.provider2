import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import { clientSources } from "@mod/clients";
import { clientsConfig } from "@mod/clients/testing";
import { type Grant, grants } from "@mod/grants";
import { listening } from "@mod/http";
import { assemble, defineModule } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import rateLimitModule from "@mod/rate-limit/module";
import { senderBindings } from "@mod/sender-binding";
import { simulatedStore } from "@mod/store/testing";
import type { SubjectKind } from "@mod/tokens";
import { afterEach, expect, it } from "vitest";
import { endpointConfig, endpointModules } from "../../../test/deployment.ts";

let stop = async () => {};
afterEach(() => stop());

/** A grant declaring `declared`, issuing one token whose subject is of the kind `issued`. */
const issuing = (grantType: string, declared: SubjectKind, issued: SubjectKind): Grant => ({
	grantType,
	readsAmbient: "none",
	subjectKind: declared,
	handle: async ({ client, issue }) => {
		const access = { subject: client.id, subjectKind: issued, issuedTo: client.id };
		const answer = await issue({ access: { ...access, audience: [], scope: [] } });
		if (answer.kind !== "issued") return answer;
		const { token, tokenType } = answer.access;
		return { kind: "issued", body: { access_token: token, token_type: tokenType } };
	},
});

/** A grant declaring a person's, issuing a person's token but answering another token in its place. */
const swapping: Grant = {
	grantType: "urn:test:swap",
	readsAmbient: "none",
	subjectKind: "user",
	handle: async ({ client, issue }) => {
		const access = { subject: "alice", subjectKind: "user" as const, issuedTo: client.id };
		const answer = await issue({ access: { ...access, audience: [], scope: [] } });
		if (answer.kind !== "issued") return answer;
		return { kind: "issued", body: { access_token: "held-elsewhere", token_type: "Bearer" } };
	},
};

/** A grant that counts its own requests, over its limit for a second and a half. */
const limited: Grant = {
	grantType: "urn:test:limited",
	readsAmbient: "none",
	handle: async () => ({ kind: "error", error: "rate_limited", status: 429, retryAfterMs: 1500 }),
};

/** The endpoint with those grants, a binding kind read from a `bind` field, and a client of version 7. */
async function serve() {
	const types = ["urn:test:own", "urn:test:mismatch", "urn:test:limited", "urn:test:swap"];
	const parts = defineModule({ name: "parts", replicaSafe: true, takes: [] }, (m) => [
		m.contribute(grants).by(() => issuing("urn:test:own", "user", "user")),
		m.contribute(grants).by(() => issuing("urn:test:mismatch", "user", "client")),
		m.contribute(grants).by(() => limited),
		m.contribute(grants).by(() => swapping),
		m.contribute(senderBindings).by(() => ({
			member: "m-test",
			tokenType: "Test",
			read: async (request) =>
				request.form.has("bind")
					? ({ kind: "bound", confirmation: "thumb" } as const)
					: ({ kind: "absent" } as const),
		})),
		m.contribute(clientSources).by(() => ({
			find: async (id) =>
				id === "listed"
					? {
							id,
							kind: "public" as const,
							method: "none",
							sections: allowancesFor({ grants: types }),
							version: 7,
						}
					: undefined,
		})),
	]);
	const recorded = auditStandIn();
	const app = await assemble({
		modules: endpointModules(
			clientAllowanceModule,
			rateLimitModule,
			recorded.module,
			simulatedStore().module,
			parts,
		),
		config: { ...endpointConfig({ issuer: "https://issuer.example" }), ...clientsConfig([]) },
		runtime: quietRuntime(),
	});
	await app.start();
	stop = () => app.stop(1000);
	const url = `http://127.0.0.1:${app.get(listening).port()}/oauth/token`;
	const post = async (grantType: string, more: Record<string, string> = {}) => {
		const res = await fetch(url, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ grant_type: grantType, client_id: "listed", ...more }),
		});
		// A grant's fault is answered with no body.
		const text = await res.text();
		const body = (text === "" ? {} : JSON.parse(text)) as Record<string, unknown>;
		return { status: res.status, retryAfter: res.headers.get("retry-after"), body };
	};
	const events = () => recorded.events.map(({ kind, attributes }) => ({ kind, attributes }));
	return { post, events };
}

it("records the client's registry version and the token's binding on what it issued", async () => {
	const { post, events } = await serve();
	const answered = await post("urn:test:own", { bind: "1" });
	expect(answered.status).toBe(200);
	expect(events()).toEqual([
		{
			kind: "token.issued",
			attributes: expect.objectContaining({
				client: "listed",
				grant_type: "urn:test:own",
				version: "7",
				binding: "m-test",
				confirmation: "thumb",
			}),
		},
	]);
});

it("answers none of a bundle whose subject's kind is not the one its grant declares", async () => {
	const { post, events } = await serve();
	const answered = await post("urn:test:mismatch");
	expect(answered.status).toBe(500);
	expect(answered.body.access_token).toBeUndefined();
	expect(events().map((e) => e.kind)).not.toContain("token.issued");
});

it("answers a grant's too many requests as 429, its wait in whole seconds", async () => {
	const { post, events } = await serve();
	expect(await post("urn:test:limited")).toEqual({
		status: 429,
		retryAfter: "2",
		body: { error: "rate_limited" },
	});
	expect(events()).toEqual([
		{
			kind: "token.issued.failure",
			attributes: expect.objectContaining({ reason: "grant_refused", error: "rate_limited" }),
		},
	]);
});

it("answers none of an answer whose access token is not the one its bundle issued", async () => {
	const { post, events } = await serve();
	const answered = await post("urn:test:swap");
	expect(answered.status).toBe(500);
	expect(answered.body.access_token).toBeUndefined();
	expect(events().map((e) => e.kind)).not.toContain("token.issued");
});
