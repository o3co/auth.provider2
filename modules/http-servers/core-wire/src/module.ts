import { readFile } from "node:fs/promises";
import { overHttp, type RequestKind } from "@mod/front-core-wire";
import { type HttpServer, httpServers, marks, policies, type Route, routes } from "@mod/http";
import { guardedRoutes } from "@mod/http/server";
import { nodeHttpServer } from "@mod/http-server";
import { defineModule, type Refusal } from "@mod/kernel";
import { heldToFloor, isFloor, tlsOptions } from "@mod/tls-options";
import { detection } from "./detection.ts";
import { dispatcher } from "./dispatch.ts";
import { listenWire } from "./listener.ts";
import type { Section } from "./section.ts";
import { section } from "./section.ts";

const files = ["certificate-file", "key-file", "front-authority-file"] as const;
const keyOf = (route: Route) => `${route.method} ${route.path}`;
const kinds = Object.keys(overHttp.operations) as RequestKind[];

/** Boot's refusals of a route at an operation's path that does not take the operation's body. */
function mistaking(all: readonly Route[]): Refusal[] {
	return kinds.flatMap((kind) => {
		const { path, body } = overHttp.operations[kind];
		const route = all.find((r) => r.method === "POST" && r.path === path);
		if (!route || (route.takes ?? ["form"]).includes(body)) return [];
		return [
			{
				where: `http.routes:POST ${path}`,
				reason: `takes no ${body} body, which the wire's ${kind} is`,
			},
		];
	});
}

/** The ordinary routes no operation reaches: no frame is handed to them, and no listener serves them. */
function unreached(all: readonly Route[]): readonly Route[] {
	const paths = new Set(kinds.map((kind) => overHttp.operations[kind].path));
	return all.filter((r) => r.exposure !== "probe" && (r.method !== "POST" || !paths.has(r.path)));
}

/** The files the section names, read at boot; or the refusal of each that cannot be read, at its key, never naming its path. */
async function read(s: Section) {
	const texts = await Promise.all(
		files.map((key) => readFile(s[key], "utf8").catch(() => undefined)),
	);
	const refusals: Refusal[] = files
		.filter((_, i) => texts[i] === undefined)
		.map((key) => ({
			where: `core-wire.${key}`,
			reason: "not readable: write the path of a PEM file",
		}));
	const [cert, key, ca] = texts as string[];
	return { refusals, cert, key, ca };
}

// Safe on many instances: each listens for its own Fronts; a cut instance is refused by the process that cut it.
export default defineModule(
	{ name: "core-wire", replicaSafe: true, section, takes: [marks, policies, routes, tlsOptions] },
	(m) => [
		m.contribute(httpServers).by(async (c) => {
			const floor = await c.get(tlsOptions);
			if (!isFloor(floor)) return c.refuse("core-wire", "takes the TLS floor tls-options makes");
			const pem = await read(c.section);
			if (pem.refusals.length > 0) return c.refuseAll(pem.refusals);
			const [all, rules, kept] = [
				await c.collect(routes),
				await c.collect(policies),
				await c.collect(marks),
			];
			const checked = guardedRoutes(all, rules, kept);
			if (checked.kind === "refused") return c.refuseAll(checked.refusals);
			const mistaken = mistaking(all);
			if (mistaken.length > 0) return c.refuseAll(mistaken);
			for (const route of unreached(all)) {
				c.log.warn("core-wire.unreached", { route: `${route.method} ${route.path}` });
			}
			const probeRoutes = all.filter((route) => route.exposure === "probe");
			const probe = nodeHttpServer({ routes: probeRoutes, rules, marks: kept });
			if (probe.kind === "refused") return c.refuseAll(probe.refusals);
			const wireRoutes = checked.routes.filter((route) => route.exposure !== "probe");
			const detect = detection(c.section["on-violation"], c.log, c.clock);
			const tls = heldToFloor(floor, {
				cert: pem.cert,
				key: pem.key,
				ca: pem.ca,
				requestCert: true,
			});
			const served = new Set(all.map(keyOf));
			const server: HttpServer = {
				serve: async (input) => {
					const same =
						input.routes.length === served.size && input.routes.every((r) => served.has(keyOf(r)));
					if (!same)
						throw new Error(
							"core-wire serves only the routes it guarded at boot, and was handed others",
						);
					const probing = await probe.server.serve({
						...input,
						routes: probeRoutes,
						settings: {
							...input.settings,
							host: c.section["probe-host"],
							port: c.section["probe-port"],
							origins: new Set(),
						},
					});
					input.log.info("core-wire.probe_listening", { port: probing.port });
					const wire = await listenWire({
						tls,
						host: input.settings.host,
						port: input.settings.port,
						connections: input.settings.limits.connections,
						handle: dispatcher(
							wireRoutes,
							input.settings.proxies,
							input.ends,
							input.log,
							input.clock,
						),
						detection: detect,
						log: input.log,
						clock: input.clock,
					}).catch(async (error: unknown) => {
						// A start that fails leaves no listener open: the probe listener is drained at once.
						await probing.drain(AbortSignal.abort());
						throw error;
					});
					return {
						port: wire.port,
						drain: async (signal) => {
							await Promise.all([wire.drain(signal), probing.drain(signal)]);
						},
					};
				},
			};
			return server;
		}),
	],
);
