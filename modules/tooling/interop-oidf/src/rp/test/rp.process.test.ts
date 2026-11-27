import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ask } from "../../scene/test/ask.ts";
import { type Scene, startScene } from "../../scene/test/scene.ts";
import { dpopKey, type Provider, type RelyingParty, relyingParty, send } from "./rp.ts";

const screen = "https://login.example.invalid";

let scene: Scene;
let provider: Provider;
const rp: RelyingParty = relyingParty("rp-oidf", "https://rp.example.invalid/cb", () => provider);
const at = (path: string, init: Parameters<typeof ask>[2]) => ask(scene, path, init);

beforeAll(async () => {
	scene = await startScene({
		host: "localhost",
		listen: "127.0.0.1",
		screen,
		clients: [rp.registered()],
	});
	provider = {
		issuer: scene.issuer,
		parUrl: `${scene.issuer}/oauth/par`,
		tokenUrl: `${scene.issuer}/oauth/token`,
	};
}, 120_000);

afterAll(async () => {
	await scene?.stop();
}, 30_000);

describe("the harness's relying party, at the scene", () => {
	it("pushes a JAR as nextgen asks, taken: a request_uri for a short while", async () => {
		const { answer } = await send(at, "/oauth/par", () => rp.par(rp.authorization()));
		expect(answer.status, `${answer.text}\n${scene.output()}`).toBe(201);
		expect(answer.json.request_uri).toMatch(/^urn:ietf:params:oauth:request_uri:/);
		expect(answer.json.expires_in).toBeTypeOf("number");
	});

	it("pushes it with a DPoP proof of the key the JAR names, the proof read: a nonce asked, then taken", async () => {
		const started = rp.authorization();
		const { answer, nonceAsked } = await send(at, "/oauth/par", (nonce) =>
			rp.par(started, { nonce }),
		);
		expect(nonceAsked).toBe(true);
		expect(answer.status, answer.text).toBe(201);
	});

	it("is refused a proof of another key than the JAR names", async () => {
		const started = rp.authorization();
		const other = dpopKey();
		const { answer } = await send(at, "/oauth/par", (nonce) =>
			rp.par(started, { by: other.proof, nonce }),
		);
		expect(answer.status, answer.text).toBe(400);
		expect(answer.json).toMatchObject({
			error: "invalid_dpop_proof",
			error_description: "the proof is not of the key the request names",
		});
	});

	it("exchanges a code the provider never issued, refused as the token endpoint refuses a grant", async () => {
		const started = rp.authorization();
		const { answer } = await send(at, "/oauth/token", (nonce) =>
			rp.token(started, "no-such-code", nonce),
		);
		expect(answer.status, answer.text).toBe(400);
		expect(answer.json.error).toBe("invalid_grant");
	});
});
