import type { BuildContext } from "@mod/kernel";
import type { Keys } from "@mod/keys";
import { keys } from "@mod/keys";
import { firstKey, hpke, payloads } from "@mod/sdk-core-wire";
import type { Users } from "@mod/users";
import type { StartOutcome } from "../contract.ts";
import type { Dispatch } from "../dispatch/dispatch.ts";
import { type Evidence, itemsOf } from "../evidence/evidence.ts";
import type { Issued, Passed } from "../issuing/issuing.ts";
import type { Nonces } from "../nonces/nonces.ts";
import { digestOf, openSealed, type SealedRequest } from "../sealed/sealed.ts";
import type { Settings } from "../section.ts";
import { codeOf } from "../tokens/tokens.ts";

/** A start answered: its code sealed to the screen, alike whatever the start came to; or refused before any of it. */
export type Started =
	| { readonly kind: "answered"; readonly sealed: { readonly enc: string; readonly ct: string } }
	| { readonly kind: "refused" }
	| { readonly kind: "withdrawn" };

/** What a start's job did, for the path to write down: never an address, an identifier or a subject. */
export interface Ended {
	readonly checked: "passed" | "failed" | "unavailable";
	readonly issued?: Issued;
	readonly faults: readonly unknown[];
}

/** How a start ended, as each kind of evidence is told: passed only where its mail went out. */
const outcomeOf = (checked: Ended["checked"], issued: Issued | undefined): StartOutcome =>
	checked === "unavailable" ? "unavailable" : issued === "sent" ? "passed" : "failed";

/**
 * A first key's start (§3.13's step 1): its nonce used once, its request opened, its subject looked
 * up and its evidence asked, every time; then its code sealed to the screen. What differs, whether
 * the subject holds a key and gets a mail, is one job put apart from the answer, for every start.
 */
export function startOver(p: {
	readonly keys: Pick<Keys, "open" | "seal">;
	readonly nonces: Nonces;
	readonly users: Pick<Required<Users>, "byIdentifier">;
	readonly evidence: Evidence;
	readonly dispatch: Dispatch;
	readonly issuing: (passed: Passed) => Promise<Issued>;
	readonly random: (bytes: number) => Uint8Array;
	readonly now: () => number;
	readonly ended: (ended: Ended) => void;
}) {
	return async (request: SealedRequest): Promise<Started> => {
		const startedAt = p.now();
		// Used once, before it is opened: a start is never taken up again; a lost answer is a new start.
		if ((await p.nonces.use(request.nonce, "start", digestOf(request))) !== "first")
			return { kind: "refused" };
		const opened = await openSealed(p.keys, "start", request, payloads.startPlain);
		if (opened.kind === "withdrawn") return opened;
		if (opened.kind !== "opened") return { kind: "refused" };
		const { identifier } = opened.plain;
		const found = await p.users.byIdentifier(identifier);
		const subject = found.kind === "user" ? found.user.subject : undefined;
		const start = { nonce: request.nonce, identifier };
		const asked = await p.evidence.ask(start, subject, itemsOf(opened.plain));
		const code = codeOf(p.random);
		/** The start's end told: issuing first where it is to run, every fault the path's own as unavailable. */
		const ending = async (issuing: boolean, before: readonly unknown[] = []) => {
			let issued: Issued | undefined;
			const faults: unknown[] = [...asked.faults, ...before];
			try {
				if (issuing && subject !== undefined && asked.checked === "passed")
					issued = await p.issuing({ subject, identifier, code, startedAt });
			} catch (fault) {
				faults.push(fault);
			}
			const checked = faults.length > asked.faults.length ? "unavailable" : asked.checked;
			const told = await asked.tell(outcomeOf(checked, issued));
			p.ended({ checked, ...(issued ? { issued } : {}), faults: [...faults, ...told] });
		};
		// Sealed before the job is put: a start that cannot be answered issues nothing, its end still told.
		const aad = firstKey.aad("start", request.nonce, opened.screen.eEnc, opened.screen.eSig);
		let box: Awaited<ReturnType<typeof p.keys.seal>>;
		try {
			box = await p.keys.seal(
				new Uint8Array(Buffer.from(opened.screen.eEnc, "base64url")),
				hpke.info.firstKeyCode,
				new TextEncoder().encode(aad),
				new TextEncoder().encode(JSON.stringify({ code })),
			);
		} catch (fault) {
			p.dispatch.put(() => ending(false, [fault]));
			throw fault;
		}
		p.dispatch.put(() => ending(true));
		return {
			kind: "answered",
			sealed: {
				enc: Buffer.from(box.enc).toString("base64url"),
				ct: Buffer.from(box.ct).toString("base64url"),
			},
		};
	};
}

/** What a start takes in a build, which the path names among its takes. */
export const startTakes = [keys] as const;

/** A start made in a build from the path's parts and users' lookup it checked: the keys its own to take. */
export async function startOf(
	c: BuildContext<Settings>,
	parts: Pick<
		Parameters<typeof startOver>[0],
		"users" | "nonces" | "evidence" | "dispatch" | "issuing" | "ended"
	>,
) {
	return startOver({
		...parts,
		keys: await c.get(keys),
		random: (n) => c.random.bytes(n),
		now: c.clock.now,
	});
}
