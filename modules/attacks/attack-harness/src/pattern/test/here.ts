import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Runtime } from "@mod/kernel";
import { entry, type PatternSpec, pattern, type SentMail } from "./pattern.ts";

/** A key as the Core publishes it: a JWK with its kid. */
export type Published = Record<string, string> & { readonly kid: string };

/** The Core assembled, as the kernel gives it: each contract it holds, by its contract. */
export interface Assembled {
	get<T>(contract: { readonly __type?: T } & object): T;
	stop(withinMs: number): Promise<void>;
}

/** The harness's Core started in this process: the Core, its wire's port, and what the operator publishes. */
export interface Here {
	readonly app: Assembled;
	readonly port: number;
	/** The authority's JWKS, the Core's ring, its sealing key, as published. */
	readonly jwks: readonly Published[];
	readonly ring: readonly Published[];
	readonly sealingKey: Published;
	/** The discovery document, as the operator publishes it for an issuer at the root. */
	readonly metadata: Readonly<Record<string, unknown>>;
}

/**
 * Starts the harness's Core in this process, on the runtime parts given (a log, a clock): the Core
 * assembled and started, its seeds imported as an operator's import run brings them, its key sets
 * and discovery document published. `sent` receives each mail. Stopped where a step after the start fails.
 */
export async function startHere(
	spec: PatternSpec,
	sent: (mail: SentMail) => void,
	runtime: Partial<Runtime> = {},
): Promise<Here> {
	const { assemble } = await entry("@mod/kernel");
	const { quietRuntime } = await entry("@mod/kernel", "./testing");
	const { listening } = await entry("@mod/http");
	const { keys } = await entry("@mod/keys");
	const { usersImport } = await entry("@mod/users");
	const { discovery } = await entry("@mod/discovery");
	const { modules, config } = await pattern(spec, sent);
	const app = await assemble({ modules, config, runtime: quietRuntime(runtime) });
	await app.start();
	const dir = await mkdtemp(join(tmpdir(), "pattern-keys-"));
	try {
		// The users an operator's import run brings, before the wire is used.
		for (const seed of spec.seeds ?? []) {
			const answer = await app.get(usersImport).record(seed);
			if (answer !== "imported") throw new Error(`users-import: ${answer}`);
		}
		// The key sets as the operator publishes them: the JWKS, and the Core's ring with its sealing key.
		const published = await app.get(keys).publish([dir]);
		if (published.code !== 0) throw new Error(`keys-publish: ${published.lines.join(" ")}`);
		const read = async (name: string) => JSON.parse(await readFile(join(dir, name), "utf8"));
		const documents = join(dir, "discovery");
		const written = await app.get(discovery).publish([documents]);
		if (written.code !== 0) throw new Error(`discovery-publish: ${written.lines.join(" ")}`);
		const coreKeys: Published[] = (await read("core-keys.json")).keys;
		const sealing = coreKeys.filter((k) => k.use === "enc");
		const [sealingKey] = sealing;
		if (sealingKey === undefined || sealing.length !== 1)
			throw new Error("not one sealing key published");
		return {
			app,
			port: app.get(listening).port(),
			jwks: (await read("jwks.json")).keys,
			ring: coreKeys.filter((k) => k.use !== "enc"),
			sealingKey,
			metadata: await read(join("discovery", ".well-known", "openid-configuration")),
		};
	} catch (error) {
		await app.stop(2000);
		throw error;
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
}
