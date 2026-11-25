import { setTimeout as sleep } from "node:timers/promises";
import { approvals } from "@mod/approvals";
import type { BuildContext } from "@mod/kernel";
import { heldKeys, passkeys, registrations } from "@mod/passkeys";
import { subjectRevocation } from "@mod/subject-revocation";
import { transparency, transparencyLog } from "@mod/transparency";
import { ceremonies } from "@mod/webauthn";
import { keyChangesOver } from "../key-change/key-change.ts";
import { type Registered, registrationOver } from "../registration/registration.ts";
import { keyRoutes } from "../routes/routes.ts";
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
] as const;

/** A look for a key change's end again: soon at first, then every 200 ms, as approvals' writer looks. */
const lookAgainMs = (look: number) => Math.min(10 * 2 ** look, 200);

/** A registration not answered, written with its reason's word alone. */
const written =
	<T>(c: Context, answer: (given: T) => Promise<Registered>) =>
	async (given: T) => {
		const registered = await answer(given);
		if (registered.kind === "refused")
			c.log.info("passkey-management.registration_refused", { reason: registered.reason });
		return registered;
	};

/** A key's registration after its creation, made from its parts in a build: its two routes. */
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
	return keyRoutes({
		register: written(c, registration.register),
		finish: written(c, registration.finish),
		window: { limit: c.section.requests, ms: c.section.window * 1000 },
	});
}
