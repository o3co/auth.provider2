import type { BuildContext } from "@mod/kernel";
import { passkeyWitnesses } from "@mod/passkey-witness";
import { users } from "@mod/users";
import { ceremonies } from "@mod/webauthn";
import { dispatchOver } from "../dispatch/dispatch.ts";
import type { Evidence } from "../evidence/evidence.ts";
import { issuingOf, issuingTakes } from "../issuing/issuing.ts";
import { type Answered, mailSideOf, mailSideTakes } from "../mail-side/mail-side.ts";
import { noncesOf, noncesTakes } from "../nonces/nonces.ts";
import { firstKeyRoutes } from "../routes/routes.ts";
import type { Settings } from "../section.ts";
import { type Ended, startOf, startTakes } from "../start/start.ts";
import { tokensOf, tokensTakes } from "../tokens/tokens.ts";

type Context = BuildContext<Settings>;

/** What the path and its units take, each once, which its package names among its own takes. */
export const pathTakes = [
	...new Set([
		users,
		passkeyWitnesses,
		ceremonies,
		...noncesTakes,
		...tokensTakes,
		...issuingTakes,
		...startTakes,
		...mailSideTakes,
	]),
];

/** A start's jobs under way at once, a fixed guard: each holds a short read, a write and a mail. */
const jobsUnderWay = 1_000;

/** What a start's job did, written down without any address, identifier or subject. */
const ending = (c: Context) => (ended: Ended) => {
	// The faults' names alone, each once: never a message, which could carry what it was about.
	const names = [...new Set(ended.faults.map((f) => (f instanceof Error ? f.name : "thrown")))];
	const fields = {
		checked: ended.checked,
		...(ended.issued ? { issued: ended.issued } : {}),
		...(names.length > 0 ? { faults: names.join(" ") } : {}),
	};
	if (names.length > 0 || ended.issued === "limited") c.log.warn("first-key.start_ended", fields);
	else c.log.info("first-key.start_ended", fields);
};

/**
 * The first key's path made from its units in a build: refused where users looks no one up by
 * identifier, no passkey witness is composed, or webauthn takes no ceremony from the mail link's
 * origin; its jobs started and stopped with the assembly.
 */
export async function pathOf(
	c: Context,
	given: { readonly evidence: Evidence; readonly dropped: () => void },
): Promise<ReturnType<typeof firstKeyRoutes>> {
	const { byIdentifier } = await c.get(users);
	if (!byIdentifier) return c.refuse("first-key", "users looks no one up by identifier");
	// Whether a subject holds a key is read with the witness, so a store that lost its keys reads as holding.
	if ((await c.collect(passkeyWitnesses)).length === 0)
		return c.refuse("first-key", "no passkey witness is composed");
	// A link to a screen no ceremony may come from would send a token no key can be made with.
	if (!(await c.get(ceremonies)).allowsOrigin(new URL(c.section["mail-link"]).origin))
		return c.refuse("first-key", "the mail link's origin is not one webauthn takes");
	const dispatch = dispatchOver({
		max: jobsUnderWay,
		told: {
			dropped: () => {
				given.dropped();
				c.log.warn("first-key.job_dropped", {});
			},
			failed: (error) =>
				c.log.warn("first-key.job_failed", {
					error: error instanceof Error ? error.name : "thrown",
				}),
		},
	});
	// Its hooks come before http's, which collects the routes after: so it is started before any
	// route is served, and stopped once http has drained, waiting for the jobs those put.
	c.onStart(() => dispatch.start());
	c.onStop((signal) => dispatch.stop(signal));
	const nonces = await noncesOf(c);
	const tokens = await tokensOf(c);
	const start = await startOf(c, {
		nonces,
		users: { byIdentifier },
		evidence: given.evidence,
		dispatch,
		issuing: await issuingOf(c, tokens.issue),
		ended: ending(c),
	});
	const side = await mailSideOf(c, { nonces, tokens, users: { byIdentifier } });
	/** A mail's side or a recovery not answered, written with its reason's word alone. */
	const written =
		<T>(event: string, answer: (given: T) => Promise<Answered>) =>
		async (given: T) => {
			const answered = await answer(given);
			if (answered.kind === "refused")
				c.log.warn(`first-key.${event}`, { refused: answered.reason });
			return answered;
		};
	return firstKeyRoutes({
		nonces,
		start,
		mail: written("mail_refused", side.mail),
		recover: written("recovery_refused", side.recover),
		window: { limit: c.section.requests, ms: c.section.window * 1000 },
	});
}
