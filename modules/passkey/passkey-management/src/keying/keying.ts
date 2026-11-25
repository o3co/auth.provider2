import { setTimeout as sleep } from "node:timers/promises";
import { approvals } from "@mod/approvals";
import { type BuildContext, Unavailable } from "@mod/kernel";
import { heldKeys, passkeyGenerations, passkeys, registrations } from "@mod/passkeys";
import { subjectRevocation } from "@mod/subject-revocation";
import { transparency, transparencyLog } from "@mod/transparency";
import { users } from "@mod/users";
import { ceremonies } from "@mod/webauthn";
import { deploymentOf, nameOf } from "../account.ts";
import { approvalOver, type Finished, type Started } from "../approval/approval.ts";
import type { ContinueStage, SignUpAsk, SignUpCreated } from "../contract.ts";
import { creationOver } from "../creation/creation.ts";
import { keyChangesOver } from "../key-change/key-change.ts";
import { type Registered, registrationOver } from "../registration/registration.ts";
import { approvalRoutes, keyRoutes } from "../routes/routes.ts";
import type { Settings } from "../section.ts";

type Context = BuildContext<Settings>;

/** What a key's registration takes, which its package names among its own takes. */
export const keyingTakes = [
	approvals,
	registrations,
	heldKeys,
	passkeys,
	ceremonies,
	subjectRevocation,
	transparency,
	transparencyLog,
	users,
	passkeyGenerations,
] as const;

/** A look for a key change's end again: soon at first, then every 200 ms, as approvals' writer looks. */
const lookAgainMs = (look: number) => Math.min(10 * 2 ** look, 200);

/** A registration or an approval not answered, written under its event with its reason's word alone. */
const written =
	<T, A extends Registered | Finished | Started>(
		c: Context,
		event: "registration_refused" | "approval_refused",
		answer: (given: T) => Promise<A>,
	) =>
	async (given: T) => {
		const answered = await answer(given);
		if (answered.kind === "refused")
			c.log.info(`passkey-management.${event}`, { reason: answered.reason });
		return answered;
	};

/** A key's approval and its registration after its creation, made from its parts in a build: their routes. */
export async function keyingOf(c: Context) {
	const settling = await c.get(passkeys);
	const keyChange = keyChangesOver({
		registrations: await c.get(registrations),
		transparency: await c.get(transparency),
		passkeys: settling,
		digest: (await c.get(transparencyLog)).digest,
		pause: (look) => sleep(lookAgainMs(look)),
		looks: 18,
	});
	const registration = registrationOver({
		approvals: await c.get(approvals),
		registrations: await c.get(registrations),
		held: await c.get(heldKeys),
		passkeys: settling,
		ceremonies: await c.get(ceremonies),
		revocation: await c.get(subjectRevocation),
		keyChange,
	});
	const window = { limit: c.section.requests, ms: c.section.window * 1000 };
	const create = creationOver({
		approvals: await c.get(approvals),
		ceremonies: await c.get(ceremonies),
		held: await c.get(heldKeys),
		generations: await c.get(passkeyGenerations),
		revocation: await c.get(subjectRevocation),
		random: (n) => c.random.bytes(n),
	});
	const deployment = deploymentOf(c.section);
	const approval = approvalOver({
		approvals: await c.get(approvals),
		passkeys: settling,
		users: await c.get(users),
		create,
		deployment,
	});
	/** A sign-up's creation (F1): its account named by the deployment and a mark of its subject. */
	const signUp = {
		create: async (ask: SignUpAsk): Promise<SignUpCreated> => {
			const made = await create({
				subject: ask.subject,
				userName: nameOf(deployment, ask.subject),
				basis: "sign-up",
				evidence: ask.tHash,
				screen: ask.screen,
				since: ask.since,
			});
			if (made.kind === "issued" || made.reason === "revoked") return made;
			// Items the schema refuses are a fault; a count reached, busy or withdrawn passes: thrown, never kept.
			if (made.reason === "items")
				throw new TypeError("passkey-management: a sign-up's creation refused");
			throw new Unavailable("passkey-management");
		},
	};
	return {
		...keyRoutes({
			finish: written(c, "registration_refused", registration.finish),
			window,
		}),
		...approvalRoutes({
			start: written(c, "approval_refused", approval.start),
			finish: written(c, "approval_refused", approval.finish),
			window,
		}),
		/** The stage `register` of `/continue`: a creation's continuation, as the registration takes it. */
		registerStage: {
			stage: "register",
			continue: async (q) => {
				// A register's continuation comes in the clear: `continuation-wire` seals no register.
				if (!("body" in q)) throw new TypeError("passkey-management: a register sealed");
				const registered = await registration.register({
					statement: q.statement,
					hash: q.hash,
					seq: q.seq,
					body: q.body,
					sig: q.signature,
				});
				if (registered.kind === "possession")
					return { kind: "statement", statement: registered.statement };
				if (registered.kind === "refused") return registered;
				throw new TypeError("passkey-management: a register answered a completion");
			},
		} satisfies ContinueStage,
		signUp,
	};
}
