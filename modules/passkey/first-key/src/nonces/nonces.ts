import type { BuildContext } from "@mod/kernel";
import type { FirstKeyStage } from "@mod/sdk-core-wire";
import type { Kept, StoredNonce } from "../contract.ts";
import { firstKeyNonces } from "../contract.ts";
import type { Settings } from "../section.ts";

/** A nonce of a first key's stage as kept: its stage, and the digest of the request that used it. */
interface NonceRecord {
	readonly stage: FirstKeyStage;
	readonly digest?: string;
}

/** A use answered: the first, the same request again, or refused (unknown, past its life, another stage or request). */
export type NonceUse = "first" | "again" | "refused";

export interface Nonces {
	/** A new nonce of the stage, living the nonce's lifetime. */
	issue(stage: FirstKeyStage): Promise<string>;
	/** Uses the nonce for the stage's request of `digest`, in one write: bound to the first, answered `again` for it alone. */
	use(nonce: string, stage: FirstKeyStage, digest: string): Promise<NonceUse>;
}

const recordOf = (kept: StoredNonce | undefined): NonceRecord | undefined =>
	kept as unknown as NonceRecord | undefined;
const stored = (r: NonceRecord) => r as unknown as StoredNonce;

/** The nonces over their store: a nonce is 32 random bytes, base64url. */
export function noncesOver(p: {
	readonly store: Kept<StoredNonce>;
	readonly random: (bytes: number) => Uint8Array;
	readonly lifetimeMs: number;
}): Nonces {
	return {
		issue: async (stage) => {
			for (;;) {
				const nonce = Buffer.from(p.random(32)).toString("base64url");
				// Two alike is all but impossible; one taken is drawn again rather than shared.
				if ((await p.store.create(nonce, stored({ stage }), p.lifetimeMs)) === "created")
					return nonce;
			}
		},
		use: async (nonce, stage, digest) => {
			const changed = await p.store.change(nonce, (current) => {
				const r = recordOf(current);
				return r?.stage === stage && r.digest === undefined
					? { value: stored({ stage, digest }) }
					: undefined;
			});
			const before = recordOf(changed?.before);
			const after = recordOf(changed?.after);
			if (after?.stage !== stage || after.digest !== digest) return "refused";
			return before?.digest === undefined ? "first" : "again";
		},
	};
}

/** What the nonces take in a build, which the path names among its takes. */
export const noncesTakes = [firstKeyNonces] as const;

/** The nonces made in a build: their store and lifetime its own to take. */
export async function noncesOf(c: BuildContext<Settings>) {
	return noncesOver({
		store: await c.get(firstKeyNonces),
		random: (n) => c.random.bytes(n),
		lifetimeMs: c.section["nonce-lifetime"] * 1000,
	});
}
