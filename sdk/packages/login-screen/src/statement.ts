import {
	type CreationPayload,
	type PossessionPayload,
	payloads,
	type StatementPayload,
	typs,
} from "@mod/sdk-core-wire";
import { type Jwk, verifyCompact } from "./jws.ts";
import { namesKeys, type ScreenKeys } from "./keys.ts";

/** Each purpose's statement, by the schema sdk-core-wire gives it. */
const schemas = {
	authorization: payloads.statement,
	creation: payloads.creation,
	possession: payloads.possession,
	"passkey-manage": payloads.passkeyManage,
} as const;
interface ByPurpose {
	readonly authorization: StatementPayload;
	readonly creation: CreationPayload;
	readonly possession: PossessionPayload;
	readonly "passkey-manage": ReturnType<typeof payloads.passkeyManage.parse>;
}
export type Purpose = keyof ByPurpose;

/** Why a statement is not read: its signature, its `typ`, its payload's shape, the screen's keys it names, its issuer. */
export type StatementError = "signature" | "typ" | "payload" | "keys" | "issuer";

export interface StatementOptions<P extends Purpose> {
	readonly purpose: P;
	/** The Core ring's public keys, as the screen's bundle fixes them. */
	readonly ring: readonly Jwk[];
	readonly keys: ScreenKeys;
	readonly issuer: string;
}

/**
 * A statement read before it is shown: signed by the Core's ring, of the statement's `typ`, of the
 * purpose's schema, naming this screen's own keys (a Front that swapped them is refused) and the
 * issuer. Its times are the Core's to hold at acceptance, not the screen's.
 */
export async function readStatement<P extends Purpose>(
	compact: string,
	options: StatementOptions<P>,
): Promise<
	| { readonly statement: ByPurpose[P]; readonly compact: string }
	| { readonly error: StatementError }
> {
	const verified = await verifyCompact(compact, options.ring);
	if (!verified) return { error: "signature" };
	if (verified.header.typ !== typs.statement) return { error: "typ" };
	if (!Object.hasOwn(schemas, options.purpose)) return { error: "payload" };
	const read = schemas[options.purpose].safeParse(verified.payload);
	if (!read.success) return { error: "payload" };
	const statement = read.data as ByPurpose[P];
	if (!namesKeys(options.keys, statement.e_enc, statement.e_sig)) return { error: "keys" };
	if (statement.iss !== options.issuer) return { error: "issuer" };
	return { statement, compact };
}
