import { createPublicKey } from "node:crypto";
import { request } from "node:https";
import { connect } from "node:tls";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type Scene, startScene } from "./scene.ts";

const screen = "https://login.example.invalid";

/** A request at the scene's issuer, trusting its front's certificate alone: its status, headers and JSON body. */
function ask(
	scene: Scene,
	path: string,
	init: {
		readonly method?: string;
		readonly form?: Record<string, string>;
		readonly origin?: string;
	} = {},
) {
	const body = init.form === undefined ? undefined : new URLSearchParams(init.form).toString();
	return new Promise<{
		status: number;
		type: string;
		headers: Record<string, unknown>;
		text: string;
		json: Record<string, unknown>;
	}>((resolve, reject) => {
		const req = request(
			`${scene.issuer}${path}`,
			{
				method: init.method ?? "GET",
				ca: scene.certificate,
				headers: {
					...(body === undefined ? {} : { "content-type": "application/x-www-form-urlencoded" }),
					...(init.origin === undefined ? {} : { origin: init.origin }),
				},
			},
			(res) => {
				let text = "";
				res.on("data", (chunk) => {
					text += chunk;
				});
				res.on("end", () =>
					resolve({
						status: res.statusCode ?? 0,
						type: String(res.headers["content-type"] ?? ""),
						headers: res.headers,
						text,
						json: text === "" ? {} : JSON.parse(text),
					}),
				);
			},
		);
		req.on("error", reject);
		req.end(body);
	});
}

let scene: Scene;

beforeAll(async () => {
	scene = await startScene({
		host: "localhost",
		listen: "127.0.0.1",
		screen,
		clients: [{ id: "rp-1", kind: "public", method: "none", sections: {} }],
	});
}, 120_000);

afterAll(async () => {
	await scene?.stop();
}, 30_000);

describe("the provider as the OIDF run meets it", () => {
	it("publishes its discovery document at the issuer, behind the https front, as generated", async () => {
		const answer = await ask(scene, "/.well-known/openid-configuration");
		expect(answer.status, scene.output()).toBe(200);
		expect(answer.type).toContain("application/json");
		expect(answer.json).toMatchObject({
			issuer: scene.issuer,
			jwks_uri: `${scene.issuer}/jwks.json`,
			pushed_authorization_request_endpoint: `${scene.issuer}/oauth/par`,
			require_pushed_authorization_requests: true,
			authorization_response_iss_parameter_supported: true,
		});
	});

	it("publishes RFC 8414's document too, the same issuer", async () => {
		const answer = await ask(scene, "/.well-known/oauth-authorization-server");
		expect(answer.status).toBe(200);
		expect(answer.json.issuer).toBe(scene.issuer);
	});

	it("serves the authority's key set where the document names it, and the Core's apart", async () => {
		type Key = { readonly kid?: string; readonly use?: string; readonly d?: unknown };
		const kids = async (path: string) => {
			const answer = await ask(scene, path);
			expect(answer.status, path).toBe(200);
			const keys = answer.json.keys as readonly Key[];
			for (const key of keys) {
				expect(key.d, path).toBeUndefined();
				// Each a public key as published, readable as one.
				expect(
					() => createPublicKey({ key, format: "jwk" } as Parameters<typeof createPublicKey>[0]),
					path,
				).not.toThrow();
			}
			return keys.map((key) => `${key.kid}/${key.use}`).sort();
		};
		expect(await kids("/jwks.json")).toEqual(["test/sig"]);
		expect(await kids("/core-keys.json")).toEqual(["core-test/sig", "seal-test/enc"]);
	});

	it("answers a pushed request through the Front, which the Core refuses over the wire", async () => {
		// A pushed request in the form the wire carries (JWSs where it names them), an assertion for a
		// public client: the Core's authentication refuses it, and the Front carries the answer back.
		const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
		const jws = (typ: string) => `${part({ alg: "ES256", typ })}.${part({})}.${"A".repeat(86)}`;
		const answer = await ask(scene, "/oauth/par", {
			method: "POST",
			form: {
				client_id: "rp-1",
				client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				client_assertion: jws("JWT"),
				request: jws("oauth-authz-req+jwt"),
			},
		});
		expect(answer.status, `${JSON.stringify(answer.json)}\n${scene.output()}`).toBe(401);
		expect(answer.json).toMatchObject({ error: "invalid_client" });
	});

	it("answers a published file as the publisher does: GET and HEAD alone, uncached, its length told", async () => {
		const refused = await ask(scene, "/jwks.json", { method: "POST" });
		expect(refused.status).toBe(405);
		expect(refused.headers.allow).toBe("GET, HEAD");
		const got = await ask(scene, "/jwks.json");
		expect(got.headers["cache-control"]).toBe("no-cache");
		expect(got.headers["content-length"]).toBe(String(Buffer.byteLength(got.text)));
		const head = await ask(scene, "/jwks.json", { method: "HEAD" });
		expect(head.status).toBe(200);
		expect(head.type).toContain("application/json");
		expect(head.headers["content-length"]).toBe(got.headers["content-length"]);
		expect(head.text).toBe("");
		// The screen's pages read it; a page of any other origin is told nothing.
		const read = await ask(scene, "/core-keys.json", { origin: screen });
		expect(read.headers.vary).toBe("Origin");
		expect(read.headers["access-control-allow-origin"]).toBe(screen);
		const stranger = await ask(scene, "/core-keys.json", {
			origin: "https://other.example.invalid",
		});
		expect(stranger.headers.vary).toBe("Origin");
		expect(stranger.headers["access-control-allow-origin"]).toBeUndefined();
	});

	it("speaks TLS 1.2 by BCP 195's suites alone at the issuer's edge", async () => {
		const { port } = new URL(scene.issuer);
		const handshake = (ciphers: string) =>
			new Promise<boolean>((resolve) => {
				const socket = connect(
					{
						host: "127.0.0.1",
						port: Number(port),
						ca: scene.certificate,
						servername: "localhost",
						maxVersion: "TLSv1.2",
						ciphers,
					},
					() => {
						socket.end();
						resolve(true);
					},
				);
				socket.on("error", () => resolve(false));
			});
		expect(await handshake("ECDHE-ECDSA-AES128-GCM-SHA256")).toBe(true);
		expect(await handshake("ECDHE-ECDSA-AES128-SHA256")).toBe(false);
	});
});
