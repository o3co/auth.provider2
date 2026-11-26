import { type Approvals, approvals } from "@mod/approvals";
import { type Audit, audit, declaredAudit } from "@mod/audit";
import { type ClaimsSelections, claimsSelections } from "@mod/claims-selection";
import type { FamilyMaker, FamilyRequest } from "@mod/code-grant";
import type { BundlePart, BundlePlaced } from "@mod/grants";
import { type BuildContext, Unavailable } from "@mod/kernel";
import { type Keys, keys } from "@mod/keys";
import { type Passkeys, passkeys } from "@mod/passkeys";
import { typs } from "@mod/sdk-core-wire";
import type { Binding } from "@mod/sender-binding";
import events from "../audit-events.ts";
import {
	allowanceMs,
	type FamilyRecord,
	nameOf,
	read,
	revokeFamily,
	sha256,
	tokenOf,
	write,
} from "../record.ts";
import { heldBy, type Listed, rootedOver } from "../rooted/rooted.ts";
import { type FamilyRecords, familyRecords } from "../store.ts";

/** What a family's founding is made over. */
export interface FoundingParts {
	readonly records: FamilyRecords;
	readonly approvals: Pick<Approvals, "rootOf">;
	readonly passkeys: Pick<Passkeys, "publicKeyOf">;
	readonly keys: Pick<Keys, "generation" | "verifyOf">;
	readonly selections: Pick<ClaimsSelections, "follow">;
	/** The delegation's length, in ms (O27). */
	readonly lifetimeMs: number;
	readonly now: () => number;
	/** A refresh token's secret: 32 random bytes, base64url. */
	readonly secret: () => string;
	/** Lists a family founded under its subject and its root key (internal module `rooted`). */
	readonly list: (entry: Listed) => Promise<void>;
	readonly audit: Audit;
}

/** What a part holds between its preparing and its commit: the record but its id, and the secret. */
interface Ready {
	readonly record: Omit<FamilyRecord, "format">;
	readonly secret: string;
}

/** A statement's issue time, in ms, as its signed `iat` says. */
const issuedAt = (jws: string) =>
	(
		JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8")) as {
			iat: number;
		}
	).iat * 1000;

const refused = (why: string) => ({ refused: why }) as const;

/**
 * Founds refresh families with code redemptions (proposal 3.9): the root read before the bundle
 * starts, the family's token signed with the bundle's record, and the family kept once the bundle is
 * taken in, beside the key it is bound to and the code it came from.
 */
export function founding(p: FoundingParts): FamilyMaker {
	/**
	 * Keeps the family once its bundle is taken in: its record, its code's link, then its key, claimed
	 * by the index's one create (Q27). Its code voided meanwhile, or its key claimed by another family
	 * first, ends it at once; a failure midway ends it too: its token is never answered.
	 */
	/** A family not founded, its key bound to another (Q27), recorded for the operator. */
	const keyBound = (subject: string, client: string, binding: Binding) =>
		declaredAudit(p.audit, events).record("refresh.key_bound", {
			subject,
			attributes: { client, binding: binding.member, thumbprint: binding.confirmation },
		});

	async function commit(ready: Ready, placed: BundlePlaced) {
		const { record } = ready;
		const ttl = record.end - p.now() + allowanceMs;
		const made = await p.records.create(
			nameOf.family(placed.id),
			write.family({ format: 1, ...record }),
			ttl,
			record.subject,
		);
		if (made === "erased") throw new Unavailable("refresh: the subject is erased");
		try {
			const linked = await p.records.change(nameOf.code(record.code), (kept) => {
				const r = read.code(kept);
				return r && { value: write.code({ ...r, family: placed.id }) };
			});
			if (!linked) {
				const link = write.code({ format: 1, subject: record.subject, family: placed.id });
				await p.records.create(nameOf.code(record.code), link, ttl, record.subject);
			}
			const code = read.code(await p.records.read(nameOf.code(record.code)));
			const key = nameOf.key(record.binding.confirmation);
			await p.records.create(key, write.key(placed.id, record.subject), ttl, record.subject);
			const claimed = read.key(await p.records.read(key))?.family;
			if (claimed !== placed.id) keyBound(record.subject, record.client, record.binding);
			if (code?.revoked || claimed !== placed.id)
				throw new Unavailable("refresh: ended as founded");
			await p.list({ subject: record.subject, family: placed.id, credential: record.credential });
			// Its root key removed since `part` read it, before it was listed: ended here, as told.
			const root = await p.passkeys.publicKeyOf(record.credential);
			if (root?.subject !== record.subject) throw new Unavailable("refresh: its root key is gone");
			await p.selections.follow(record.code, placed.id, ttl);
		} catch (error) {
			await revokeFamily(p.records, placed.id).catch(() => undefined);
			throw error;
		}
	}

	/** The Core generation whose ring signed a statement: this one's, or the one before. */
	const generationOf = async (statement: string) => {
		const now = p.keys.generation();
		for (const g of [now, now - 1].filter((g) => g >= 1)) {
			if ((await p.keys.verifyOf(g, statement, typs.statement)).kind === "valid") return g;
		}
		return undefined;
	};

	return {
		part: async (asked: FamilyRequest) => {
			const root = await p.approvals.rootOf(asked.statement);
			if (!root) return refused("the approval it rests on is gone");
			const key = await p.passkeys.publicKeyOf(root.credential);
			if (!key || key.subject !== asked.subject) return refused("the key it rests on is gone");
			if (!asked.binding) return refused("no key the family is bound to");
			// One family a key (Q27): a key the index holds, its family live or not, until that family's end.
			if ((await p.records.read(nameOf.key(asked.binding.confirmation))) !== undefined) {
				keyBound(asked.subject, asked.clientId, asked.binding);
				return refused("the key is bound to another family");
			}
			const generation = await generationOf(root.statement);
			if (generation === undefined) return refused("the statement it rests on does not verify");
			const secret = p.secret();
			const record = {
				subject: asked.subject,
				client: asked.clientId,
				session: asked.session,
				scope: [...asked.scope],
				audience: [...asked.audience],
				amr: [...asked.amr],
				...(asked.acr === undefined ? {} : { acr: asked.acr }),
				authTime: asked.approvedAt,
				end: issuedAt(root.statement) + p.lifetimeMs,
				binding: { ...asked.binding },
				statement: root.statement,
				assertion: root.assertion,
				credential: root.credential,
				registration: key.registration,
				publicKey: key.publicKey,
				generation,
				secret: sha256(secret),
				code: asked.code,
			};
			const ready: Ready = { record, secret };
			const part: BundlePart = {
				frame: "family",
				prepare: async () => ({ prepared: ready, digest: sha256(JSON.stringify(record)) }),
				sign: async (prepared, _receipt, placed) => tokenOf(placed.id, (prepared as Ready).secret),
				commit: (prepared, placed) => commit(prepared as Ready, placed),
			};
			return part;
		},
		revoke: async (code, subject) => {
			const name = nameOf.code(code);
			const marked = await p.records.change(name, (kept) => {
				const r = read.code(kept);
				return r && !r.revoked ? { value: write.code({ ...r, revoked: true }) } : undefined;
			});
			// None founded yet: marked under its subject so that none is, kept as long as a redemption may
			// still commit. With no subject, the code's record is gone: none is founded from it any more.
			if (!marked && subject !== undefined) {
				const mark = write.code({ format: 1, subject, revoked: true });
				await p.records.create(name, mark, p.lifetimeMs, subject);
			}
			const family = read.code(await p.records.read(name))?.family;
			if (family !== undefined) await revokeFamily(p.records, family);
		},
	};
}

/** What the founding takes from the composition. */
export const foundingTakes = [
	familyRecords,
	approvals,
	passkeys,
	keys,
	claimsSelections,
	audit,
] as const;

export const foundingIn = async (
	c: Pick<BuildContext<unknown>, "get" | "clock" | "random">,
	lifetimeMs: number,
) =>
	founding({
		records: await c.get(familyRecords),
		approvals: await c.get(approvals),
		passkeys: await c.get(passkeys),
		keys: await c.get(keys),
		selections: await c.get(claimsSelections),
		lifetimeMs,
		now: c.clock.now,
		secret: () => Buffer.from(c.random.bytes(32)).toString("base64url"),
		list: rootedOver({
			records: await c.get(familyRecords),
			lifetimeMs,
			now: c.clock.now,
			held: heldBy(await c.get(passkeys)),
		}).list,
		audit: await c.get(audit),
	});
