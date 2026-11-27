import { generateKeyPairSync, KeyObject } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage } from "node:http";
import { createServer as createTlsServer } from "node:https";
import { connect, type Socket } from "node:net";
import { join } from "node:path";
import { frontRelayConfig } from "@mod/front-relay/testing";
import { httpConfig } from "@mod/http/testing";
import { kernelConfig } from "@mod/kernel";
import { promiseNames } from "@mod/promises";
import { crlOf, dns, issue, pemOf } from "@mod/x509-path/testing";
import { describe, expect, it } from "vitest";
import { freePort, generated, listening, scripted } from "../src/testing.ts";
import { devConfig } from "./configs.ts";
import {
	auditedThroughFront,
	bootMs,
	certificates,
	coreAndFront,
	dir,
	events,
	held,
	heldFixtures,
	heldWhile,
	memoryCore,
	registry,
	relay,
} from "./held.ts";

// The flip's evidence beyond boot (permission-model-plan.md, "The flip's evidence: plan"): E1's legs,
// which reach no outside system, E2's, the Core reaching out, and E3a's, its revocation check. Each runs through the manifest's
// `start`, under audit (the held line, no event line, and what the leg does) and under enforce (the
// same answer). Network is held only where Node takes --allow-net, so a zero says nothing of the
// network on Node 24: E2's legs count from Node 26 runs. prom-client tries /proc/self/limits at registration
// everywhere, and reads /proc/self/fd and /proc/self/status at a scrape on Linux alone: locally the
// scrape shows its route and the limits grant, on the Linux runners its /proc reads as well.
// The fakes and the held runs are held.ts's, shared with E3b's file.

heldFixtures();

/**
 * A scrape of `path` on the app's port: 200, Prometheus' text, the process's CPU counted; on Linux the
 * metrics its /proc reads make too (open and most file descriptors, resident memory), so a grant they
 * need is shown used, not only unrefused.
 */
async function scraped(port: number, path = "/metrics") {
	const answer = await fetch(`http://127.0.0.1:${port}${path}`);
	expect(answer.status).toBe(200);
	const text = await answer.text();
	expect(text).toContain("auth_provider_process_cpu_user_seconds_total");
	if (process.platform !== "linux") return;
	// Gauges start at 0, so a read is shown by a value above it: the open descriptors and the
	// resident memory /proc/self/fd and /proc/self/status give. The limit's is a number or Nan.
	const value = (name: string) =>
		Number(new RegExp(`^auth_provider_process_${name} (\\S+)$`, "m").exec(text)?.[1]);
	for (const name of ["open_fds", "resident_memory_bytes"])
		expect(value(name), name).toBeGreaterThan(0);
	expect(text).toMatch(/^auth_provider_process_max_fds /m);
}

const pem = () =>
	generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({
		type: "pkcs8",
		format: "pem",
	}) as string;

/** The dev pattern's configuration on `port`, its keys as given. */
async function dev(port: number, keys?: readonly Record<string, string>[]) {
	const issuer = `http://127.0.0.1:${await freePort()}/tenant`;
	const config = devConfig({ port, relay: relay.port, registry, issuer });
	return keys === undefined ? config : { ...config, "keys-local": { keys } };
}

describe("a generated app held beyond its boot (the flip's evidence, E1)", () => {
	it(
		"nextgen-dev: keys-local's keys from a file and inline, read at its boot; a scrape; no event under audit, the same under enforce",
		async () => {
			const app = await generated({ pattern: "nextgen-dev" });
			try {
				const port = await freePort();
				// The Core's key from a file the configuration names; the others inline (mixed members).
				const file = join(dir, "core-test.pem");
				await writeFile(file, pem());
				const keys = [
					{ kid: "test", pem: pem() },
					{ kid: "core-test", file },
					{ kid: "seal-test", pem: pem() },
				];
				const config = await dev(port, keys);
				// keys-local reads every key at boot, refusing one it cannot, so listening shows the file key
				// read; a key in memory signs with no access the model holds.
				for (const mode of ["audit", "enforce"] as const)
					await heldWhile(app.dir, config, mode, port, () => scraped(port));
			} finally {
				await app.remove();
			}
		},
		2 * bootMs + 10_000,
	);

	it(
		"nextgen-front: a scrape; no event under audit, the same under enforce",
		async () => {
			const app = await generated({ pattern: "nextgen-front" });
			try {
				const port = await freePort();
				const config = {
					...kernelConfig(),
					...httpConfig({ port, "public-origin": "https://login.example.invalid" }),
					...frontRelayConfig(certificates, { "core-port": await freePort() }),
				};
				for (const mode of ["audit", "enforce"] as const)
					await heldWhile(app.dir, config, mode, port, () => scraped(port));
			} finally {
				await app.remove();
			}
		},
		2 * bootMs + 10_000,
	);

	it(
		"nextgen-dev: an application.conf including a file outside the app, which includes a nested one and probes a missing optional one; no event under audit, the same under enforce",
		async () => {
			const app = await generated({ pattern: "nextgen-dev" });
			try {
				const port = await freePort();
				const outside = join(dir, "outside");
				await mkdir(outside, { recursive: true });
				// Outside the app, which grants its own directory whole: the included file, the missing
				// optional one it probes, and the nested one it includes, which moves the scrape's path, so
				// answering there shows each read (or probed) held.
				await writeFile(join(outside, "far.conf"), 'include "absent"\ninclude "deeper"\n');
				await writeFile(
					join(outside, "deeper.conf"),
					'metrics-prometheus { path = "/far-metrics" }\n',
				);
				const conf = join(app.dir, "config", "application.conf");
				await writeFile(
					conf,
					`${await readFile(conf, "utf8")}\ninclude file("${join(outside, "far.conf")}")\n`,
				);
				const config = await dev(port);
				for (const mode of ["audit", "enforce"] as const)
					await heldWhile(app.dir, config, mode, port, () => scraped(port, "/far-metrics"));
			} finally {
				await app.remove();
			}
		},
		2 * bootMs + 10_000,
	);

	it(
		"nextgen-dev: refused at its boot under enforce: 78 and its own refused lines, held, and no event line",
		async () => {
			const app = await generated({ pattern: "nextgen-dev" });
			try {
				const port = await freePort();
				const strict = {
					...(await dev(port)),
					promises: { required: [promiseNames.newAuthorization] },
				};
				const run = await scripted(app.dir, "start", strict, { APP_PERMISSION: "enforce" });
				try {
					// Where it wrongly boots, it listens: told at once, not at the test's limit.
					const ended = await Promise.race([
						run.exited,
						listening(port, run, bootMs).then((up) => (up ? "up" : "neither exited nor listened")),
					]);
					expect(ended, run.out()).toBe(78);
					expect(run.out()).toMatch(/refused promises\.required/);
					expect(run.out()).toContain(held("enforce"));
					expect(events(run.out())).toEqual([]);
				} finally {
					await run.stop();
				}
			} finally {
				await app.remove();
			}
		},
		bootMs + 10_000,
	);
});

/** An audit collector on every interface, dual stack (the system's lookup answers `localhost` ::1 first): each request's path and body. */
async function collector() {
	const got: { path: string; body: string }[] = [];
	const server = createServer((request, response) => {
		let body = "";
		request.on("data", (chunk) => {
			body += chunk;
		});
		request.on("end", () => {
			got.push({ path: request.url ?? "", body });
			response.writeHead(204).end();
		});
	});
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen({ port: 0, host: "::", ipv6Only: false }, resolve);
	});
	const address = server.address();
	const port = typeof address === "object" && address !== null ? address.port : 0;
	return { port, got, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}

/** The audit event a refused client's token request records, as audit-http posts it. */
const refusedClient = "client.authentication.failure";

describe("a generated Core held while it reaches out (the flip's evidence, E2: Node 26 alone holds its network)", () => {
	it(
		"nextgen-core: an audit event posted to a plain-loopback collector, resolved in the process; no event under audit, the same under enforce",
		() =>
			coreAndFront(async ({ core, front }) => {
				const sink = await collector();
				try {
					const config = memoryCore(await freePort(), {
						"audit-http": { url: `http://localhost:${sink.port}/events` },
						outbound: { allow: ["localhost"], "plain-loopback": [`localhost:${sink.port}`] },
					});
					for (const mode of ["audit", "enforce"] as const) {
						sink.got.length = 0;
						await auditedThroughFront(core, front, config, mode, () => sink.got.length > 0);
						expect(sink.got[0]?.path).toBe("/events");
						expect(sink.got[0]?.body).toContain(refusedClient);
					}
				} finally {
					await sink.close();
				}
			}),
		4 * bootMs + 2 * 10_000,
	);

	it(
		"nextgen-core: under enforce, a name the hosts file lacks (audit.example) asked of DNS and unanswered, nothing refused; the query shown asked by a run whose network is withheld",
		() =>
			coreAndFront(async ({ core, front }) => {
				const config = memoryCore(await freePort());
				// The http receiver's loss as the network's: a refused query would be told as an event,
				// which heldWhile's zero refuses, so the loss's line alone never tells a refusal apart.
				// Only lines ended by a newline are read: the last may still be arriving.
				const lost = (out: string) =>
					out
						.split("\n")
						.slice(0, -1)
						.some((line) => {
							if (!line.includes('"audit.receiver_losing"')) return false;
							try {
								const read = JSON.parse(line);
								return read.receiver === "http" && read.failure === "Unavailable";
							} catch {
								// Another line cut into it: not the loss's line.
								return false;
							}
						});
				await auditedThroughFront(core, front, config, "enforce", lost);
				// The control: with the Core's network withheld, audit tells the query it would refuse,
				// naming the name asked (c-ares is refused there even under audit, so the post is lost).
				// Only a Node taking --allow-net holds the network, so only there is it told.
				if (!process.allowedNodeEnvironmentFlags.has("--allow-net")) return;
				const file = join(core.dir, "permissions.json");
				const kept = await readFile(file, "utf8");
				const withheld = JSON.parse(kept);
				withheld.processes.start.network = false;
				await writeFile(file, JSON.stringify(withheld));
				try {
					const out = await auditedThroughFront(core, front, config, "audit", lost, {}, "some");
					expect(
						events(out).some((line) => line.includes('"resource":"audit.example."')),
						out,
					).toBe(true);
				} finally {
					await writeFile(file, kept);
				}
			}),
		4 * bootMs + 2 * 10_000,
	);

	it(
		"nextgen-core: under enforce, helper resolution: the child process granted and warned of, and a lookup through the helper answering (localhost), the event posted",
		() =>
			coreAndFront(async ({ core, front }) => {
				const sink = await collector();
				try {
					const config = memoryCore(await freePort(), {
						"audit-http": { url: `http://localhost:${sink.port}/events` },
						outbound: {
							resolution: "helper",
							allow: ["localhost"],
							"plain-loopback": [`localhost:${sink.port}`],
						},
					});
					const out = await auditedThroughFront(
						core,
						front,
						config,
						"enforce",
						() => sink.got.length > 0,
					);
					expect(out).toContain(
						"warn app-permissions: child processes are allowed, for @mod/outbound",
					);
					expect(sink.got[0]?.body).toContain(refusedClient);
				} finally {
					await sink.close();
				}
			}),
		2 * bootMs + 10_000,
	);
});

/**
 * An https audit collector for audit.example, its certificate from a test root naming a CRL at
 * crl.example, and a loopback CONNECT proxy: every tunnel led to the collector, each target it was
 * asked kept, and a plain-http GET in absolute form for the root's CRL answered with it (the leaf
 * listed as revoked where `revoked`). The root's PEM, for NODE_EXTRA_CA_CERTS (read by Node outside
 * the permission model, so it needs no grant). Whatever was opened is closed by `close`, a failed
 * start included.
 */
async function revocationWorld(at: string, revoked = false) {
	const root = await issue({ cn: "evidence root", ca: true });
	const leaf = await issue({
		cn: "audit.example",
		by: root,
		eku: ["1.3.6.1.5.5.7.3.1"],
		san: [dns("audit.example")],
		crl: "http://crl.example/root.crl",
	});
	const crl = Buffer.from(await crlOf({ by: root, ...(revoked ? { revoked: [leaf] } : {}) }));
	const key = KeyObject.from(leaf.keys.privateKey).export({ type: "pkcs8", format: "pem" });
	const got: { path: string; body: string }[] = [];
	const crlAsked: string[] = [];
	const connected: string[] = [];
	const sockets: Socket[] = [];
	const servers: { close: (done: () => void) => unknown }[] = [];
	const close = async () => {
		for (const socket of sockets) socket.destroy();
		await Promise.all(
			servers.map((server) => new Promise<void>((done) => server.close(() => done()))),
		);
	};
	const listened = (server: ReturnType<typeof createServer> | ReturnType<typeof createTlsServer>) =>
		new Promise<number>((resolve, reject) => {
			server.once("error", reject);
			server.listen(0, "127.0.0.1", () => resolve((server.address() as { port: number }).port));
		});
	try {
		const collectorServer = createTlsServer(
			{ cert: pemOf(leaf.der), key },
			(request: IncomingMessage, response) => {
				let body = "";
				request.on("data", (chunk) => {
					body += chunk;
				});
				request.on("end", () => {
					got.push({ path: request.url ?? "", body });
					response.writeHead(204).end();
				});
			},
		);
		servers.push(collectorServer);
		const collectorPort = await listened(collectorServer);
		const proxyServer = createServer((request, response) => {
			crlAsked.push(request.url ?? "");
			if (request.url === "http://crl.example/root.crl") {
				response.writeHead(200, { "content-type": "application/pkix-crl" }).end(crl);
				return;
			}
			response.writeHead(404).end();
		});
		proxyServer.on("connect", (request: IncomingMessage, client: Socket) => {
			connected.push(request.url ?? "");
			const upstream = connect(collectorPort, "127.0.0.1", () => {
				client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
				upstream.pipe(client);
				client.pipe(upstream);
			});
			upstream.on("error", () => client.destroy());
			client.on("error", () => upstream.destroy());
			sockets.push(client, upstream);
		});
		servers.push(proxyServer);
		const proxyPort = await listened(proxyServer);
		const ca = join(at, `evidence-root-${proxyPort}.pem`);
		await writeFile(ca, pemOf(root.der));
		return { ca, proxyPort, got, crlAsked, connected, close };
	} catch (error) {
		await close();
		throw error;
	}
}

/** The Core's configuration reaching audit.example over https through `proxyPort`, its CRL at crl.example. */
const throughProxy = (port: number, proxyPort: number) =>
	memoryCore(port, {
		"audit-http": { url: "https://audit.example/events" },
		outbound: {
			allow: ["audit.example", "crl.example"],
			proxy: `http://127.0.0.1:${proxyPort}`,
			revocation: { hosts: ["crl.example"] },
		},
	});

/** A revocation verdict the Core tells: revoked, unconfirmed, or no check at all. */
const verdictTold = /outbound\.revocation_(revoked|unconfirmed|unchecked)/;

describe("a generated Core held while it checks a peer's revocation (the flip's evidence, E3a: Node 26 alone holds its network)", () => {
	it(
		"nextgen-core: an audit event posted over https through a proxy, the peer's CRL fetched and checked; no event under audit, the same under enforce",
		() =>
			coreAndFront(async ({ core, front }) => {
				let world: Awaited<ReturnType<typeof revocationWorld>> | undefined;
				try {
					world = await revocationWorld(dir);
					const config = throughProxy(await freePort(), world.proxyPort);
					for (const mode of ["audit", "enforce"] as const) {
						const w = world;
						w.got.length = 0;
						w.crlAsked.length = 0;
						w.connected.length = 0;
						const out = await auditedThroughFront(
							core,
							front,
							config,
							mode,
							() => w.got.length > 0,
							{ NODE_EXTRA_CA_CERTS: w.ca },
						);
						expect(w.got[0]?.path).toBe("/events");
						expect(w.got[0]?.body).toContain(refusedClient);
						// The name went to the proxy unresolved, and the CRL came through it.
						expect(w.connected).toContain("audit.example:443");
						expect(w.crlAsked).toContain("http://crl.example/root.crl");
						expect(out).not.toMatch(verdictTold);
					}
				} finally {
					await world?.close();
				}
			}),
		4 * bootMs + 2 * 10_000,
	);

	it(
		"nextgen-core: under enforce, the peer revoked in the CRL fetched: told revoked (0.20 warns, and still sends), so the CRL judged is the one fetched",
		() =>
			coreAndFront(async ({ core, front }) => {
				let world: Awaited<ReturnType<typeof revocationWorld>> | undefined;
				try {
					world = await revocationWorld(dir, true);
					const w = world;
					const out = await auditedThroughFront(
						core,
						front,
						throughProxy(await freePort(), w.proxyPort),
						"enforce",
						(o) => o.includes("outbound.revocation_revoked") && w.got.length > 0,
						{ NODE_EXTRA_CA_CERTS: w.ca },
					);
					expect(out).toMatch(/outbound\.revocation_revoked/);
				} finally {
					await world?.close();
				}
			}),
		2 * bootMs + 10_000,
	);
});
