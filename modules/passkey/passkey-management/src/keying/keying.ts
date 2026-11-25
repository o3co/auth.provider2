import { setTimeout as sleep } from "node:timers/promises";
import { approvals } from "@mod/approvals";
import type { BuildContext } from "@mod/kernel";
import { heldKeys, passkeyGenerations, passkeys, registrations } from "@mod/passkeys";
import { subjectRevocation } from "@mod/subject-revocation";
import { transparency, transparencyLog } from "@mod/transparency";
import { users } from "@mod/users";
import { ceremonies } from "@mod/webauthn";
import { approvalOver, type Finished, type Started } from "../approval/approval.ts";
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
	const approval = approvalOver({
		approvals: await c.get(approvals),
		passkeys: settling,
		users: await c.get(users),
		create: creationOver({
			approvals: await c.get(approvals),
			ceremonies: await c.get(ceremonies),
			held: await c.get(heldKeys),
			generations: await c.get(passkeyGenerations),
			revocation: await c.get(subjectRevocation),
			random: (n) => c.random.bytes(n),
		}),
		// The deployment's name, by default the mail link's host, as long as `account-name` may be.
		deployment: c.section["account-name"] ?? new URL(c.section["mail-link"]).hostname.slice(0, 50),
	});
	return {
		...keyRoutes({
			register: written(c, "registration_refused", registration.register),
			finish: written(c, "registration_refused", registration.finish),
			window,
		}),
		...approvalRoutes({
			start: written(c, "approval_refused", approval.start),
			finish: written(c, "approval_refused", approval.finish),
			window,
		}),
	};
}
