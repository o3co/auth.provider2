import { Unavailable } from "@mod/kernel";
import type { PasskeyRemoval, Passkeys } from "@mod/passkeys";
import {
	allowanceMs,
	listedPerBucket,
	type RootedList,
	read,
	revokeFamily,
	rootedOf,
	write,
} from "../record.ts";
import type { FamilyRecords, StoredFamilyRecord } from "../store.ts";

/** What the rooted lists are kept over: the records, the delegation's length, the clock, and the root keys held now. */
export interface RootedParts {
	readonly records: FamilyRecords;
	/** The delegation's length (L): no family lives longer from its founding. */
	readonly lifetimeMs: number;
	readonly now: () => number;
	/** Whether the subject holds the root key of this credential now: its family is never ended. */
	readonly held: (subject: string, credential: string) => Promise<boolean>;
}

/**
 * A subject's families ended by their root key (Q46): `end`, those whose root key (their approval's)
 * is the credential, as the rules' DelDrop drops them; `endAll`, all of them, as a reset or an
 * erasure boundary does. Either keeps a family whose root key the subject holds now: a removal told
 * late never ends a family of the generation after it. Ended as a revocation ends them; the key each is bound to stays held to the
 * family's end (Q27). Only the families listed. Throws Unavailable where the store cannot tell.
 */
export interface RootedFamilies {
	end(subject: string, credential: string): Promise<void>;
	endAll(subject: string): Promise<void>;
}

/** A family as a rooted list names it: its subject, its id and its root key's credential. */
export interface Listed {
	readonly subject: string;
	readonly family: string;
	readonly credential: string;
}

/**
 * A subject's families by their root key (Q46): each listed in its founding's bucket of L, whose
 * record lives 2L and a margin, so a family live now is in this bucket or the one before; ended by
 * the key's credential, or all of a subject's. A family past a bucket's `listedPerBucket` is not
 * listed: the log's rules and its end still hold it.
 */
export function rootedOver(p: RootedParts) {
	const bucketOf = (at: number) => Math.floor(at / p.lifetimeMs);
	const added =
		(entry: Listed) =>
		(kept: StoredFamilyRecord): { readonly value: StoredFamilyRecord } | undefined => {
			const r = read.rooted(kept);
			if (!r || r.families.length >= listedPerBucket) return undefined;
			if (r.families.some((f) => f.family === entry.family)) return undefined;
			const families = [...r.families, { family: entry.family, credential: entry.credential }];
			return { value: write.rooted({ ...r, families }) };
		};

	/** Lists a family founded now; past its bucket's count, none. Unavailable where the store cannot tell. */
	async function list(entry: Listed): Promise<void> {
		const name = rootedOf(entry.subject, bucketOf(p.now()));
		if (await p.records.change(name, added(entry))) return;
		const first: RootedList = {
			format: 1,
			subject: entry.subject,
			families: [{ family: entry.family, credential: entry.credential }],
		};
		const ttl = 2 * p.lifetimeMs + allowanceMs;
		const made = await p.records.create(name, write.rooted(first), ttl, entry.subject);
		if (made === "erased") throw new Unavailable("refresh: the subject is erased");
		if (made === "exists") await p.records.change(name, added(entry));
	}

	/** Ends each family a subject's rooted lists name, in this bucket, the one before and the one after (clocks drift), whose credential is asked. */
	async function ended(subject: string, asked: (credential: string) => boolean) {
		const now = bucketOf(p.now());
		for (const bucket of [now - 1, now, now + 1]) {
			const r = read.rooted(await p.records.read(rootedOf(subject, bucket)));
			if (r?.subject !== subject) continue;
			for (const f of r.families) {
				if (!asked(f.credential)) continue;
				// A root key held now (a new generation's after a reset, told late) keeps its family.
				if (await p.held(subject, f.credential)) continue;
				await revokeFamily(p.records, f.family);
			}
		}
	}

	const rooted: RootedFamilies = {
		end: (subject, credential) => ended(subject, (c) => c === credential),
		endAll: (subject) => ended(subject, () => true),
	};
	return { list, rooted };
}

/**
 * `passkeys`' word for a removal, read at this boundary alone: a credential its subject holds no more
 * ends the families rooted in it; a subject left with no key (a reset, an erasure boundary) ends all.
 * A failure is thrown, so the next settle tells it again.
 */
export const removalOver = (rooted: RootedFamilies): PasskeyRemoval => ({
	removed: (subject, credential, emptied) =>
		emptied ? rooted.endAll(subject) : rooted.end(subject, credential),
});

/** Whether a subject holds a root key now, as `passkeys` answers its active keys. */
export const heldBy =
	(keys: Pick<Passkeys, "publicKeyOf">) => async (subject: string, credential: string) =>
		(await keys.publicKeyOf(credential))?.subject === subject;
