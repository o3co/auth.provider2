import { execFileSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { publishServe, type Serving } from "../src/serve.ts";

let dir = "";
let outside = "";
let serving: Serving;
const reader = "http://127.0.0.1:8080";

/** A request as sent, the path written as given (fetch would resolve its dot segments). */
const sent = (path: string, method = "GET", origin?: string) =>
	new Promise<{ status: number; headers: Record<string, unknown>; body: string }>((done, fail) => {
		const url = new URL(serving.origin);
		const r = request(
			{ host: url.hostname, port: url.port, path, method, headers: origin ? { origin } : {} },
			(response) => {
				let body = "";
				response.on("data", (c) => {
					body += c;
				});
				response.on("end", () =>
					done({ status: response.statusCode ?? 0, headers: response.headers, body }),
				);
			},
		);
		r.on("error", fail);
		r.end();
	});

beforeAll(async () => {
	dir = await mkdtemp(join(tmpdir(), "publish-serve-"));
	outside = await mkdtemp(join(tmpdir(), "publish-serve-outside-"));
	await mkdir(join(dir, "tenant", ".well-known"), { recursive: true });
	await writeFile(join(dir, "tenant", ".well-known", "openid-configuration"), '{"issuer":"x"}\n');
	await writeFile(join(dir, "tenant", "jwks.json"), '{"keys":[]}\n');
	await writeFile(join(dir, "tenant", "core-keys.json"), '{"keys":[1]}\n');
	await writeFile(join(outside, "secret.json"), '{"secret":true}\n');
	await symlink(join(outside, "secret.json"), join(dir, "tenant", "link.json"));
	// An issuer's path as a publisher writes it: percent-encoded, as its URL is.
	await mkdir(join(dir, "tenant%20one"), { recursive: true });
	await writeFile(join(dir, "tenant%20one", "jwks.json"), '{"keys":[2]}\n');
	await writeFile(join(dir, "tenant", "denied.json"), "{}\n");
	await chmod(join(dir, "tenant", "denied.json"), 0);
	// A FIFO no writer opens: reading it would wait for ever.
	execFileSync("mkfifo", [join(dir, "tenant", "fifo.json")]);
	const run = await publishServe([dir, "http://127.0.0.1:0", reader]);
	if (!run.serving) throw new Error(run.lines.join("\n"));
	serving = run.serving;
});

afterAll(async () => {
	await serving?.close();
	await rm(dir, { recursive: true, force: true });
	await rm(outside, { recursive: true, force: true });
});

describe("publish-serve", () => {
	it("serves each file at its path under the directory, with or without a trailing /, as JSON", async () => {
		for (const path of ["/tenant/.well-known/openid-configuration", "/tenant/jwks.json/"]) {
			const got = await sent(path);
			expect(got.status, path).toBe(200);
			expect(got.headers["content-type"]).toBe("application/json");
		}
		expect((await sent("/tenant/jwks.json")).body).toBe('{"keys":[]}\n');
		const head = await sent("/tenant/jwks.json", "HEAD");
		expect([head.status, head.body]).toEqual([200, ""]);
	});

	it("serves a percent-encoded path at the name it is written under, as the publisher wrote it", async () => {
		const got = await sent("/tenant%20one/jwks.json");
		expect([got.status, got.body]).toEqual([200, '{"keys":[2]}\n']);
	});

	it("lets the reader origins given read, and no other", async () => {
		const read = await sent("/tenant/core-keys.json", "GET", reader);
		expect(read.headers["access-control-allow-origin"]).toBe(reader);
		expect(read.headers.vary).toBe("Origin");
		const other = await sent("/tenant/core-keys.json", "GET", "http://127.0.0.1:9999");
		expect(other.headers["access-control-allow-origin"]).toBeUndefined();
		expect(other.headers.vary).toBe("Origin");
	});

	it("answers no file outside the directory, no directory, and no method but GET and HEAD", async () => {
		for (const path of [
			"/",
			"/tenant",
			"/tenant/../../etc/passwd",
			"/tenant/%2e%2e/%2e%2e/etc/passwd",
			"/tenant%2fjwks.json",
			"/tenant/link.json",
			"/tenant/denied.json",
			"/tenant/fifo.json",
			"/tenant/%zz",
			"/missing.json",
		]) {
			expect((await sent(path)).status, path).toBe(404);
		}
		const posted = await sent("/tenant/jwks.json", "POST");
		expect([posted.status, posted.headers.allow]).toEqual([405, "GET, HEAD"]);
	});
});

describe("publish-serve's arguments", () => {
	it("refuses an origin that is not plain http on loopback, or not an origin", async () => {
		for (const origin of [
			"https://127.0.0.1:0",
			"http://example.com:0",
			"http://10.0.0.1:0",
			"http://127.0.0.1:0/",
			"http://127.0.0.1:0/tenant",
			"http://127.0.0.1:0?x",
		]) {
			const run = await publishServe([dir, origin]);
			expect([run.code, run.serving], origin).toEqual([1, undefined]);
		}
	});

	it("refuses a reader that is not an origin, and a directory that is none", async () => {
		expect((await publishServe([dir, "http://127.0.0.1:0", "*"])).code).toBe(1);
		expect((await publishServe([dir, "http://127.0.0.1:0", `${reader}/`])).code).toBe(1);
		expect((await publishServe([join(dir, "missing"), "http://127.0.0.1:0"])).code).toBe(1);
		expect((await publishServe([dir])).code).toBe(64);
	});

	it("binds a localhost name to 127.0.0.1, never resolving it", async () => {
		const run = await publishServe([dir, "http://dev.localhost:0"]);
		try {
			expect(run.code).toBe(0);
			expect(run.serving?.origin).toMatch(/^http:\/\/dev\.localhost:\d+$/);
			const port = new URL(run.serving?.origin ?? "").port;
			const got = await new Promise<number>((done, fail) => {
				const r = request({ host: "127.0.0.1", port, path: "/tenant/jwks.json" }, (response) => {
					response.resume();
					done(response.statusCode ?? 0);
				});
				r.on("error", fail);
				r.end();
			});
			expect(got).toBe(200);
		} finally {
			await run.serving?.close();
		}
	});
});
