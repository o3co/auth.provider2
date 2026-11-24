import { canonicalText, continuation as continued, hpke, type payloads } from "@mod/sdk-core-wire";
import { base64url, deepFreeze, digest, utf8 } from "./bytes.ts";
import { type Sealed, sealTo } from "./hpke.ts";
import type { Jwk } from "./jws.ts";
import { namesKeys, type ScreenKeys } from "./keys.ts";
import { readStatement, type StatementError } from "./statement.ts";

type ManageStatement = ReturnType<typeof payloads.passkeyManage.parse>;

/** A passkey-manage statement as `read` gave it. Only `read` makes one. */
export interface ReadManage {
	readonly statement: ManageStatement;
	readonly compact: string;
}

const issued = new WeakSet<ReadManage>();

/** A `passkey-manage` statement read before its `get()`: of its purpose, naming this screen's keys, the issuer's. */
async function read(
	statement: string,
	options: { readonly ring: readonly Jwk[]; readonly keys: ScreenKeys; readonly issuer: string },
): Promise<{ readonly manage: ReadManage } | { readonly error: StatementError }> {
	const read = await readStatement(statement, { ...options, purpose: "passkey-manage" });
	if ("error" in read) return read;
	const manage = deepFreeze({ statement: read.statement, compact: read.compact }) as ReadManage;
	issued.add(manage);
	return { manage };
}

/**
 * A delete's or a rename's continuation (V24): its body, of its stage's shape, signed with E_sig over
 * the plaintext body's hash (`continuation.of`, as every stage), and the body with its signature
 * sealed to the Core's sealing key, padded to one length and bound to the stage, the statement and
 * the sequence. The Front sees neither. A resend sends the same sealed value again, kept by the
 * caller: sealing anew gives other bytes for the same body.
 */
async function continuation(
	manage: ReadManage,
	stage: "delete" | "rename",
	seq: number,
	body: unknown,
	options: { readonly keys: ScreenKeys; readonly sealingKey: Uint8Array },
): Promise<
	{ readonly sealed: Sealed } | { readonly error: "statement" | "keys" | "sequence" | "body" }
> {
	if (!issued.has(manage)) return { error: "statement" };
	const { e_enc, e_sig } = manage.statement;
	if (!namesKeys(options.keys, e_enc, e_sig)) return { error: "keys" };
	if (!Number.isSafeInteger(seq) || seq < 1 || seq > 16) return { error: "sequence" };
	const read = continued.bodies[stage].safeParse(body);
	if (!read.success) return { error: "body" };
	const h = await digest(manage.compact);
	const input = continued.of(stage, h, seq, await digest(canonicalText(read.data)));
	const signature = await crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		options.keys.signing.privateKey,
		utf8(input),
	);
	const plain = continued.plainOf(stage, read.data, base64url(new Uint8Array(signature)));
	if (plain === undefined) return { error: "body" };
	const sealed = await sealTo(
		options.sealingKey,
		utf8(hpke.info.continuation),
		utf8(continued.aad(stage, h, seq)),
		utf8(plain),
	);
	return { sealed };
}

/** The keys' management on the screen: read its statement, seal a delete's or a rename's continuation. */
export const management = Object.freeze({ read, continuation });
