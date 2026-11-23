import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import type { ConnectionOptions } from "node:tls";
import { httpServers, marks, policies, routes } from "@mod/http";
import { nodeHttpServer } from "@mod/http-server";
import { contract, defineModule, probes, type Refusal } from "@mod/kernel";
import { heldToFloor, isFloor, type TlsOptions, tlsOptions } from "@mod/tls-options";
import { type CoreLink, coreLink } from "./link.ts";
import { relayFallback, shadowing } from "./relay.ts";
import { type Section, section } from "./section.ts";

/** The files the section names, by key. */
const files = ["certificate-file", "key-file", "core-authority-file"] as const;

/** Boot's refusals of a file that cannot be read, at its key, never naming its path. */
async function unreadable(s: Section): Promise<Refusal[]> {
	const read = await Promise.all(
		files.map((key) =>
			readFile(s[key]).then(
				() => true,
				() => false,
			),
		),
	);
	return files
		.filter((_, i) => !read[i])
		.map((key) => ({
			where: `front-relay.${key}`,
			reason: "not readable: write the path of a PEM file",
		}));
}

/** The connection's options, the files read anew, held to the TLS floor; SNI only for a name, never an address. */
async function connectionOptions(floor: TlsOptions, s: Section): Promise<ConnectionOptions> {
	const [cert, key, ca] = await Promise.all(files.map((k) => readFile(s[k], "utf8")));
	const name = s["server-name"] ?? s["core-host"];
	return heldToFloor(floor, {
		host: s["core-host"],
		port: s["core-port"],
		...(isIP(name) ? {} : { servername: name }),
		cert,
		key,
		ca,
	});
}

/** The link to the Core, one per assembly, closed at stop. */
const link = contract<CoreLink>("front-relay.link");

// Safe on many instances: each holds only its own connection to the Core.
export default defineModule(
	{ name: "front-relay", replicaSafe: true, section, takes: [marks, policies, routes, tlsOptions] },
	(m) => [
		m.provide(link).by(async (c) => {
			const floor = await c.get(tlsOptions);
			if (!isFloor(floor)) return c.refuse("front-relay", "takes the TLS floor tls-options makes");
			const refusals = await unreadable(c.section);
			if (refusals.length > 0) return c.refuseAll(refusals);
			const made = coreLink(() => connectionOptions(floor, c.section), c.section.timeout, c.log);
			c.onStop(async () => made.close());
			return made;
		}),
		m.contribute(httpServers).by(async (c) => {
			const local = await c.collect(routes);
			// The Front's own route answers where it takes a relayed path (R10): told, never refused.
			for (const route of shadowing(local)) {
				c.log.warn("front-relay.shadowed", { route: `POST ${route.path}` });
			}
			const built = nodeHttpServer({
				routes: local,
				rules: await c.collect(policies),
				marks: await c.collect(marks),
				fallback: relayFallback(await c.get(link), c.log),
			});
			return built.kind === "refused" ? c.refuseAll(built.refusals) : built.server;
		}),
		m.contribute(probes).by(async (c) => {
			const made = await c.get(link);
			return { name: "core", check: (signal: AbortSignal) => made.reach(signal) };
		}),
	],
);
