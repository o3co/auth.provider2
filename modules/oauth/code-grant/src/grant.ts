import { clientAllowance } from "@mod/client-allowance";
import type { Grant, GrantOutcome } from "@mod/grants";
import { sameSecret, Unavailable } from "@mod/kernel";
import { sameBinding } from "@mod/sender-binding";
import type { Sessions } from "@mod/session";
import { type AccessGrant, referenceOf } from "@mod/tokens";
import { type CodeRecord, digestOf, fromStored, s256, toStored, verifierShape } from "./codes.ts";
import {
	type ApprovedFacts,
	codeGrantType,
	type FamilyMaker,
	type FamilyRequest,
	type IdTokenMaker,
	openid,
	type RedemptionHook,
} from "./contract.ts";
import {
	createRedemptionRecord,
	isRedeemed,
	noteToken,
} from "./redemption-record/redemption-record.ts";
import type { CodeStore, RedemptionRecords } from "./store/store.ts";

/** One answer for every refused code, so it tells nothing about why. */
const refused: GrantOutcome = {
	kind: "error",
	error: "invalid_grant",
	description: "invalid code",
};
/** An answer that leaves the code unused. */
const malformed = (description: string): GrantOutcome => ({
	kind: "error",
	error: "invalid_request",
	description,
});

const accessOf = (record: CodeRecord, clientId: string): AccessGrant => ({
	subject: record.subject,
	subjectKind: "user",
	issuedTo: clientId,
	audience: record.audience,
	scope: record.scope,
	amr: record.amr,
	authenticatedAt: record.authenticatedAt,
	...(record.authenticatedAtUnknown ? { authenticatedAtUnknown: true } : {}),
	...(record.acr !== undefined ? { acr: record.acr } : {}),
});

/** An ID token's request from a code's record; a record of an openid code holds its nonce and approval. */
const idTokenOf = (record: CodeRecord, clientId: string, code: string) => {
	const { nonce, approval } = record;
	if (nonce === undefined || approval === undefined)
		throw new TypeError("code-grant: an openid code without its nonce or its approval");
	return {
		...approval,
		subject: record.subject,
		clientId,
		nonce,
		amr: record.amr,
		...(record.acr === undefined ? {} : { acr: record.acr }),
		scope: record.scope,
		session: record.session,
		code,
	};
};

/** A family's request from a code's record, rooted with its approval's facts. */
const familyOf = (record: CodeRecord, clientId: string, code: string): FamilyRequest => ({
	...(record.approval as ApprovedFacts & { statement: string }),
	subject: record.subject,
	clientId,
	scope: record.scope,
	audience: record.audience,
	amr: record.amr,
	...(record.acr === undefined ? {} : { acr: record.acr }),
	session: record.session,
	...(record.binding ? { binding: record.binding } : {}),
	code,
});

/** The refresh grant's type (RFC 6749 §6), which a client must be allowed for a family to be founded. */
const refreshGrantType = "refresh_token";

export function codeGrant(parts: {
	readonly store: CodeStore;
	readonly redemptionRecords: RedemptionRecords;
	readonly sessions: Sessions;
	readonly settle: (name: string) => Promise<void>;
	readonly hooks: readonly RedemptionHook[];
	/** The ID token's maker, where one is composed. */
	readonly idToken?: IdTokenMaker;
	/** The refresh family's maker, where one is composed. */
	readonly family?: FamilyMaker;
	readonly now: () => number;
}): Grant {
	const { store, redemptionRecords, sessions, settle, hooks, idToken, family, now } = parts;
	/** Runs each hook; one that fails voids the code, so what was issued is revoked, and the failure goes on. */
	const runHooks = async (name: string, run: (hook: RedemptionHook) => Promise<void>) => {
		try {
			for (const hook of hooks) await run(hook);
		} catch (error) {
			await settle(name);
			throw error;
		}
	};
	/** Whether the code's session enters at use: not closed or ended. */
	const enters = async (session: string) => (await sessions.entryOf(session)).kind === "entered";
	return {
		grantType: codeGrantType,
		readsAmbient: "none",
		targets: true,
		handle: async ({ client, param, admits, issue, binding, target }) => {
			const code = param("code");
			const redirectUri = param("redirect_uri");
			const verifier = param("code_verifier");
			if (!code || !redirectUri || !verifier) {
				return malformed("code, redirect_uri and code_verifier are required");
			}
			if (!verifierShape.test(verifier)) return malformed("malformed code_verifier");
			const name = store.nameOf(code);
			// Presented by its own client, at its redirect URI, with its verifier, and proved by the key
			// the authorization asked for ahead: or by no key, where it asked for none.
			const presented = (r: CodeRecord) =>
				r.clientId === client.id &&
				r.redirectUri === redirectUri &&
				sameSecret(s256(verifier), r.challenge) &&
				sameBinding(binding, r.binding);
			// Asked before use, by whoever may redeem it; with the code's one audience, the rule only refuses.
			const peeked = await store.update(name, () => undefined);
			const unused = peeked && fromStored(peeked.before);
			if (unused?.state === "issued" && presented(unused)) {
				const asked = target(unused.audience, (audience) => unused.audience.includes(audience));
				if (asked.kind === "error") return asked;
				const admitted = await admits(accessOf(unused, client.id), { session: unused.session });
				if (admitted.kind === "refused") return admitted;
			}
			// Used up before it is checked: of two racing uses, only the one that turned it consumed goes on.
			const used = await store.update(name, (stored) => {
				const r = fromStored(stored);
				return r?.state === "issued" ? { value: toStored({ ...r, state: "consumed" }) } : undefined;
			});
			const record = used && fromStored(used.before);
			if (!record) {
				// A code gone, its own record ended, may still have been redeemed: its token is revoked
				// from its redemption record, which outlives it.
				if (await isRedeemed(redemptionRecords, name)) await settle(name);
				return refused;
			}
			if (record.state === "consumed") {
				await settle(name);
				return refused;
			}
			if (!presented(record)) return refused;
			// A code whose root was never set roots in no approval: used up, it issues nothing.
			const root = record.root;
			if (root === undefined) return refused;
			// A code asking an ID token where none is made gives nothing, rather than a token alone.
			const asksIdToken = record.scope.includes(openid);
			if (asksIdToken && !idToken) {
				return { kind: "error", error: "invalid_scope", description: "no ID token is issued" };
			}
			const entry = await sessions.entryOf(record.session);
			if (entry.kind !== "entered") return refused;
			// Asked again on what was used up: a look before use that missed the code asked nothing.
			const again = target(record.audience, (audience) => record.audience.includes(audience));
			if (again.kind === "error") return again;
			// Its record is made once used up and before issuing (use-up, create, issue, note), under
			// its subject's tombstone (`redemption-record`): a subject erased meanwhile gets no token.
			const redemption = digestOf(code);
			const { made, tokenEnd } = await createRedemptionRecord(
				redemptionRecords,
				name,
				record.subject,
				now,
				redemption,
			);
			if (made === "erased") {
				await settle(name);
				return refused;
			}
			// Only this request turned the code consumed: a record there already is no state it knows.
			if (made !== "created") throw new Unavailable("code-grant");
			await runHooks(name, (hook) => hook.pin(redemption, record.subject));
			const idParts =
				asksIdToken && idToken
					? [await idToken.part(idTokenOf(record, client.id, redemption))]
					: [];
			// A family for a client allowed to refresh, of a code rooted with its approval's facts.
			const founds =
				family &&
				record.approval?.statement !== undefined &&
				clientAllowance.allowsGrant(client, refreshGrantType);
			const founded = founds
				? await family.part(familyOf(record, client.id, redemption))
				: undefined;
			if (founded && "refused" in founded) return refused;
			const parts = [...idParts, ...(founded ? [founded] : [])];
			// One bundle, rooted in the code's approval by its code. The token ends no later than its
			// session, nor later than the allowance before its record's end.
			const allowed = await issue(
				{
					root,
					via: { via: "code", code: redemption },
					access: accessOf(record, client.id),
					parts,
				},
				{ session: record.session, notAfter: Math.min(entry.endsAt, tokenEnd) },
			);
			if (allowed.kind === "refused") return allowed;
			const [idTokenIssued, refreshIssued] = [
				idParts.length > 0 ? allowed.parts?.[0] : undefined,
				founded ? allowed.parts?.[idParts.length] : undefined,
			];
			if ((idParts.length > 0 && !idTokenIssued) || (founded && !refreshIssued))
				throw new TypeError("code-grant: a bundle answered without a part it asked");
			const issued = allowed.access;
			// Noted on its record, which keeps its end; one gone meanwhile (erased) gets no token answered.
			const after = await noteToken(redemptionRecords, name, {
				reference: referenceOf(issued),
				expiresAt: issued.expiresAt,
			});
			// Read again after issuing: a reuse marks the code before any redemption record may be there.
			const reread = await store.update(name, () => undefined);
			const left = reread && fromStored(reread.before);
			// A reuse, a logout, the subject's erasure or the code's end while the token was being made
			// voids it: a code that ended answers no token, as it would be one never used up.
			if (!after || !left || after.void || left.void || !(await enters(record.session))) {
				await settle(name);
				return refused;
			}
			const access = { id: issued.id, expiresAt: issued.expiresAt };
			const redeemed = { redemption, subject: record.subject, scope: record.scope, access };
			await runHooks(name, (hook) => hook.redeemed(redeemed));
			return {
				kind: "issued",
				body: {
					access_token: issued.token,
					token_type: issued.tokenType,
					expires_in: issued.expiresIn,
					scope: record.scope.join(" "),
					...(idTokenIssued === undefined ? {} : { id_token: idTokenIssued }),
					...(refreshIssued === undefined ? {} : { refresh_token: refreshIssued }),
				},
			};
		},
	};
}
