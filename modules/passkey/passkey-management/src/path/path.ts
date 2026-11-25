import { approvals } from "@mod/approvals";
import type { BuildContext } from "@mod/kernel";
import { keys } from "@mod/keys";
import { mail } from "@mod/mail";
import { passkeyWitnesses } from "@mod/passkey-witness";
import { heldKeys, passkeyGenerations, passkeys } from "@mod/passkeys";
import { subjectRevocation } from "@mod/subject-revocation";
import { users } from "@mod/users";
import { ceremonies } from "@mod/webauthn";
import { firstKeyNonces, firstKeyTokens } from "../contract.ts";
import { creationOver } from "../creation/creation.ts";
import { dispatchOver } from "../dispatch/dispatch.ts";
import type { Evidence } from "../evidence/evidence.ts";
import { issuingOver } from "../issuing/issuing.ts";
import { type Answered, mailSideOver } from "../mail-side/mail-side.ts";
import { noncesOver } from "../nonces/nonces.ts";
import { firstKeyRoutes } from "../routes/routes.ts";
import type { Settings } from "../section.ts";
import { type Ended, startOver } from "../start/start.ts";
import { tokensOver } from "../tokens/tokens.ts";

type Context = BuildContext<Settings>;

/** What the path takes, which its package names among its own takes. */
export const pathTakes = [
	keys,
	users,
	passkeys,
	heldKeys,
	passkeyGenerations,
	passkeyWitnesses,
	mail,
	firstKeyNonces,
	firstKeyTokens,
	approvals,
	ceremonies,
	subjectRevocation,
] as const;

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
	if (names.length > 0 || ended.issued === "limited")
		c.log.warn("passkey-management.start_ended", fields);
	else c.log.info("passkey-management.start_ended", fields);
};

/**
 * The first key's path made from its parts in a build: refused where users looks no one up by
 * identifier or no passkey witness is composed; its jobs started and stopped with the assembly.
 */
export async function pathOf(
	c: Context,
	given: { readonly evidence: Evidence; readonly dropped: () => void },
): Promise<ReturnType<typeof firstKeyRoutes>> {
	const bytes = (n: number) => c.random.bytes(n);
	const found = await c.get(users);
	if (!found.byIdentifier)
		return c.refuse("passkey-management", "users looks no one up by identifier");
	// Whether a subject holds a key is read with the witness, so a store that lost its keys reads as holding.
	if ((await c.collect(passkeyWitnesses)).length === 0)
		return c.refuse("passkey-management", "no passkey witness is composed");
	// A link to a screen no ceremony may come from would send a token no key can be made with.
	if (!(await c.get(ceremonies)).allowsOrigin(new URL(c.section["mail-link"]).origin))
		return c.refuse("passkey-management", "the mail link's origin is not one webauthn takes");
	const lifetimeMs = c.section["token-lifetime"] * 1000;
	const dispatch = dispatchOver({
		max: jobsUnderWay,
		told: {
			dropped: () => {
				given.dropped();
				c.log.warn("passkey-management.job_dropped", {});
			},
			failed: (error) =>
				c.log.warn("passkey-management.job_failed", {
					error: error instanceof Error ? error.name : "thrown",
				}),
		},
	});
	// Its hooks come before http's, which collects the routes after: so it is started before any
	// route is served, and stopped once http has drained, waiting for the jobs those put.
	c.onStart(() => dispatch.start());
	c.onStop((signal) => dispatch.stop(signal));
	const tokens = tokensOver({
		store: await c.get(firstKeyTokens),
		random: bytes,
		now: c.clock.now,
		lifetimeMs,
		tries: c.section["code-tries"],
	});
	const nonces = noncesOver({
		store: await c.get(firstKeyNonces),
		random: bytes,
		lifetimeMs: c.section["nonce-lifetime"] * 1000,
	});
	const held = await c.get(heldKeys);
	const opening = await c.get(keys);
	const start = startOver({
		keys: opening,
		nonces,
		users: { byIdentifier: found.byIdentifier },
		evidence: given.evidence,
		dispatch,
		issuing: issuingOver({
			passkeys: await c.get(passkeys),
			held,
			users: found,
			issue: tokens.issue,
			mail: await c.get(mail),
			link: c.section["mail-link"],
			lifetimeMs,
		}),
		random: bytes,
		now: c.clock.now,
		ended: ending(c),
	});
	const side = mailSideOver({
		keys: opening,
		nonces,
		users: { byIdentifier: found.byIdentifier },
		tokens,
		create: creationOver({
			approvals: await c.get(approvals),
			ceremonies: await c.get(ceremonies),
			held,
			generations: await c.get(passkeyGenerations),
			revocation: await c.get(subjectRevocation),
			random: bytes,
		}),
	});
	/** A mail's side or a recovery not answered, written with its reason's word alone. */
	const written =
		<T>(event: string, answer: (given: T) => Promise<Answered>) =>
		async (given: T) => {
			const answered = await answer(given);
			if (answered.kind === "refused" || answered.kind === "unavailable")
				c.log.warn(`passkey-management.${event}`, { [answered.kind]: answered.reason });
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
