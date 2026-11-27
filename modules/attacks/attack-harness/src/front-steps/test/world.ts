import { badFront } from "../../front/front.ts";
import { holdCertificates } from "../../pattern/test/certificates.ts";
import { type StartedCore, startCore } from "../../pattern/test/launch.ts";
import type { PatternSpec } from "../../pattern/test/pattern.ts";
import {
	origin,
	type Person,
	provider,
	relyingParties,
	screenOrigin,
	world as worldOn,
} from "../../world/test/world.ts";

export { origin, type Person, provider, screenOrigin };

/**
 * A step file's world: one Core of the default pattern started in a process of its own with the
 * relying parties of `clientIds` and the spec's changes, its Fronts dishonest ones, and the Core as
 * started (its log, its published keys) beside it.
 */
export async function world(
	clientIds: readonly string[],
	more: Pick<
		PatternSpec,
		"signedClients" | "change" | "seeds" | "outbound" | "released" | "onViolation"
	> & {
		/** More clients the operator registers, beside the relying parties': each as `clients`' `registered` takes it. */
		readonly clients?: readonly unknown[];
	} = {},
) {
	const { clients, ...pattern } = more;
	const held = await holdCertificates();
	let core: StartedCore;
	let rps: Awaited<ReturnType<typeof relyingParties>>["rps"];
	try {
		const made = await relyingParties(clientIds);
		rps = made.rps;
		core = await startCore({
			certificates: held.certificates,
			origin,
			screen: screenOrigin,
			clients: [...made.clients, ...(clients ?? [])],
			...pattern,
		});
	} catch (error) {
		await held.letGo();
		throw error;
	}
	const on = worldOn({ ...core, certificates: held.certificates }, rps, badFront);
	return {
		...on,
		core,
		stop: async () => {
			try {
				await on.stop();
			} finally {
				await held.letGo();
			}
		},
	};
}

export type World = Awaited<ReturnType<typeof world>>;
