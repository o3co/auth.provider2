import { mkdir, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { metadata, issuer as named } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { discovery, type Published } from "./contract.ts";

const openid = "/.well-known/openid-configuration";
const oauth = "/.well-known/oauth-authorization-server";
const usage: Published = { lines: ["usage: discovery-publish <directory>"], code: 64 };

/**
 * Where clients look for an issuer's document: OpenID Connect Discovery appends its name to the
 * issuer, RFC 8414 inserts its name before the issuer's path. Without a path both are at the root;
 * with one, the root would name another issuer. The path is the URL's own, its dot segments
 * resolved and the rest percent-encoded, so no place leaves the directory.
 */
function placesOf(issuer: string): readonly string[] {
	const path = new URL(issuer).pathname.replace(/\/$/, "");
	return [`${path}${openid}`, `${oauth}${path}`];
}

export default defineModule(
	{ name: "discovery", replicaSafe: true, takes: [named, metadata] },
	(m) => [
		m.provide(discovery).by(async (c) => {
			const issuer = (await c.get(named)).url;
			// A value with no elements is left out, as an absent one is (OpenID Connect Discovery §4.2,
			// RFC 8414 §3.2), whichever module contributed it.
			const items = (await c.collect(metadata)).filter(
				(item) =>
					item.value !== undefined && !(Array.isArray(item.value) && item.value.length === 0),
			);
			// The issuer comes first and is the configured one; built once, so every run writes the same.
			const text = `${JSON.stringify({
				issuer,
				...Object.fromEntries(items.map((item) => [item.name, item.value])),
			})}\n`;
			return {
				publish: async (args) => {
					const [dir] = args;
					if (args.length !== 1 || !dir) return usage;
					const lines: string[] = [];
					for (const place of placesOf(issuer)) {
						const path = join(dir, place);
						await mkdir(dirname(path), { recursive: true });
						// Written beside it, then renamed, so a reader never sees half a document.
						await writeFile(`${path}.writing`, text, { flag: "w" });
						await rename(`${path}.writing`, path);
						lines.push(`wrote ${path}`);
					}
					return { lines, code: 0 };
				},
			};
		}),
	],
);
