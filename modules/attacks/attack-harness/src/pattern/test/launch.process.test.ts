import { wireClient } from "@mod/core-wire/testing";
import { wireCertificates } from "@mod/front-relay/testing";
import { afterAll, beforeAll, expect, it } from "vitest";
import { honestRelay } from "../../relay/relay.ts";
import { readyWithinMs, type StartedCore, startCore } from "./launch.ts";

let certificates: Awaited<ReturnType<typeof wireCertificates>>;
let core: StartedCore | undefined;
beforeAll(async () => {
	certificates = await wireCertificates();
	core = await startCore({
		certificates,
		origin: "https://issuer.example",
		screen: "https://login.example",
		clients: [],
	});
	// The launcher's own window, and the certificates' making, bound the hook.
}, readyWithinMs + 10_000);
afterAll(async () => {
	await core?.stop();
	await certificates?.remove();
});

it("starts the default pattern in a process of its own, reached over the wire alone", async () => {
	if (core === undefined) throw new Error("no Core");
	expect(core.ring.length).toBeGreaterThan(0);
	expect(core.sealingKey).toMatchObject({ kty: "EC", crv: "P-256", use: "enc" });
	expect(core.jwks.length).toBeGreaterThan(0);
	const wire = await wireClient(core.port, certificates);
	try {
		const front = honestRelay(wire, "203.0.113.20");
		// A token request for a client no operator registered: the Core's own refusal, relayed.
		const answered = await front.post({
			path: "/oauth/token",
			body: {
				grant_type: "authorization_code",
				code: "abc",
				redirect_uri: "https://rp.example/cb",
				code_verifier: "v".repeat(43),
				client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				client_assertion: "a.b.c",
			},
		});
		expect(answered).toMatchObject({ status: 401, body: { error: "invalid_client" } });
		expect(answered.wire?.outcome).toBe("refused");
	} finally {
		wire.close();
	}
});
