import {
	canonicalText,
	continuation as continued,
	hpke,
	type payloads,
	payloads as schemas,
} from "@mod/sdk-core-wire";
import { base64url, deepFreeze, digest, utf8 } from "./bytes.ts";
import { openCompletion } from "./completion.ts";
import { creationOf, type ReadCreation } from "./first-key.ts";
import { type Sealed, sealTo } from "./hpke.ts";
import type { Jwk } from "./jws.ts";
import { namesKeys, type ScreenKeys } from "./keys.ts";
import { readStatement, type StatementError } from "./statement.ts";

type ManageStatement = ReturnType<typeof payloads.passkeyManage.parse>;
type AddStatement = ReturnType<typeof payloads.passkeyAdd.parse>;
type KeyRow = ReturnType<typeof payloads.completions.passkeyManage.parse>["keys"][number];

/** The keys' management's two ceremonies (V22): a key added, or the keys listed, deleted or renamed. */
export type ManagementPurpose = "passkey-add" | "passkey-manage";

/** A management statement as `read` gave it. Only `read` makes one. */
export interface ReadManage {
	readonly statement: AddStatement | ManageStatement;
	readonly compact: string;
}

const issued = new WeakSet<ReadManage>();

interface ReadOptions {
	readonly ring: readonly Jwk[];
	readonly keys: ScreenKeys;
	readonly issuer: string;
}

/**
 * A management statement read before its `get()`: of the purpose the screen asked for (another's is
 * a `payload`), naming this screen's keys, the issuer's. Its times are the Core's to hold.
 */
async function read(
	statement: string,
	options: ReadOptions & { readonly purpose: ManagementPurpose },
): Promise<{ readonly manage: ReadManage } | { readonly error: StatementError }> {
	const read = await readStatement(statement, options);
	if ("error" in read) return read;
	const manage = deepFreeze({ statement: read.statement, compact: read.compact }) as ReadManage;
	issued.add(manage);
	return { manage };
}

/** Why an approval's completion is not taken: a completion's refusal, or a passkey-add's creation not of this approval. */
export type ManagementFinishError =
	| "statement"
	| "open"
	| "signature"
	| "typ"
	| "payload"
	| "issuer"
	| "assertion"
	| "continued"
	| "creation"
	| "basis"
	| "evidence";

/** A management statement's completion: opened under its purpose and hash, the ring's, of its purpose's schema, binding the statement and the assertion, the issuer's. */
async function completionOf(
	manage: ReadManage,
	sealed: Sealed,
	options: ReadOptions & { readonly assertion: Uint8Array },
): Promise<
	| {
			readonly done:
				| ReturnType<typeof payloads.completions.passkeyAdd.parse>
				| ReturnType<typeof payloads.completions.passkeyManage.parse>;
			readonly h: string;
	  }
	| {
			readonly error:
				| "open"
				| "signature"
				| "typ"
				| "payload"
				| "issuer"
				| "statement"
				| "assertion";
	  }
> {
	const { purpose } = manage.statement;
	const h = await digest(manage.compact);
	const opened = await openCompletion(sealed, {
		...options,
		aad: utf8(hpke.completionAad(purpose, h)),
	});
	if ("error" in opened) return opened;
	const completion = (
		purpose === "passkey-add" ? schemas.completions.passkeyAdd : schemas.completions.passkeyManage
	).safeParse(opened.payload);
	if (!completion.success) return { error: "payload" };
	const done = completion.data;
	if (done.iss !== options.issuer) return { error: "issuer" };
	if (done.t_hash !== h) return { error: "statement" };
	if (done.assertion_hash !== (await digest(options.assertion))) return { error: "assertion" };
	return { done, h };
}

/**
 * The approval's completion (`approvalFinish`, sealed): opened under `completionAad` of the
 * statement's purpose and hash, the Core's ring's, of that purpose's completion, binding the statement
 * and the assertion sent. A passkey-manage's is the keys' list, a listing's never a rename's
 * (`continued`). A passkey-add's carries the creation that goes on: read as a statement naming
 * this screen's keys, of passkey-add's path (`basis`), its evidence this statement's hash; the next
 * steps are the first key's (`createOptions`, `continuation`, `readPossession`).
 */
async function finish(
	manage: ReadManage,
	sealed: Sealed,
	options: ReadOptions & { readonly assertion: Uint8Array },
): Promise<
	| { readonly creation: ReadCreation }
	| { readonly keys: readonly KeyRow[] }
	| { readonly error: ManagementFinishError }
> {
	if (!issued.has(manage)) return { error: "statement" };
	const taken = await completionOf(manage, sealed, options);
	if ("error" in taken) return taken;
	const { done, h } = taken;
	if (done.purpose === "passkey-manage") {
		if (done.continued !== undefined) return { error: "continued" };
		return { keys: done.keys };
	}
	const creation = await readStatement(done.creation, { ...options, purpose: "creation" });
	if ("error" in creation) return { error: "creation" };
	if (creation.statement.creation.basis !== "passkey-add") return { error: "basis" };
	if (creation.statement.creation.evidence !== h) return { error: "evidence" };
	return { creation: creationOf(creation.statement, creation.compact) };
}

/** A delete's or a rename's continuation as `continuation` sent it: its statement, stage, sequence, body and the body's hash. Only `continuation` makes one. */
export interface Continued {
	readonly manage: ReadManage;
	readonly stage: "delete" | "rename";
	readonly seq: number;
	readonly body: { readonly credential_id: string; readonly label?: string };
	/** The hash of the body's `canonicalText`, the one its signature covers. */
	readonly bodyHash: string;
}
const sent = new WeakSet<Continued>();

/** Whether `continuation` sent this one. Not offered: for this package's key change reading. */
export const wasSent = (continuation: Continued): boolean => sent.has(continuation);

/**
 * A delete's or a rename's continuation (V24): its body, of its stage's shape, signed with E_sig over
 * the plaintext body's hash (`continuation.of`, as every stage), and the body with its signature
 * sealed to the Core's sealing key, padded to one length and bound to the stage, the statement and
 * the sequence. The Front sees neither. A resend sends the same sealed value again, kept by the
 * caller: sealing anew gives other bytes for the same body. What was sent (`Continued`) is what the
 * answer is read against.
 */
async function continuation(
	manage: ReadManage,
	stage: "delete" | "rename",
	seq: number,
	body: unknown,
	options: { readonly keys: ScreenKeys; readonly sealingKey: Uint8Array },
): Promise<
	| { readonly sealed: Sealed; readonly sent: Continued }
	| { readonly error: "statement" | "keys" | "sequence" | "body" }
> {
	if (!issued.has(manage) || manage.statement.purpose !== "passkey-manage")
		return { error: "statement" };
	const { e_enc, e_sig } = manage.statement;
	if (!namesKeys(options.keys, e_enc, e_sig)) return { error: "keys" };
	if (!Number.isSafeInteger(seq) || seq < 1 || seq > 16) return { error: "sequence" };
	const read = continued.bodies[stage].safeParse(body);
	if (!read.success) return { error: "body" };
	const h = await digest(manage.compact);
	const bodyHash = await digest(canonicalText(read.data));
	const input = continued.of(stage, h, seq, bodyHash);
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
	const made: Continued = deepFreeze({ manage, stage, seq, body: read.data, bodyHash });
	sent.add(made);
	return { sealed, sent: made };
}

/**
 * A rename's answer (`continue`'s rename, sealed): the passkey-manage completion as `finish` takes
 * it, with `continued` naming exactly the rename sent (its stage, sequence and body's hash): one of
 * another sequence or body, or none, is refused. Answers the new keys' list.
 */
async function renamed(
	rename: Continued,
	sealed: Sealed,
	options: ReadOptions & { readonly assertion: Uint8Array },
): Promise<
	| { readonly keys: readonly KeyRow[] }
	| { readonly error: "sent" | Exclude<ManagementFinishError, "creation" | "basis" | "evidence"> }
> {
	if (!sent.has(rename) || rename.stage !== "rename") return { error: "sent" };
	const taken = await completionOf(rename.manage, sealed, options);
	if ("error" in taken) return taken;
	const { done } = taken;
	if (done.purpose !== "passkey-manage") return { error: "payload" };
	const named = done.continued;
	if (named?.seq !== rename.seq || named.body_hash !== rename.bodyHash)
		return { error: "continued" };
	return { keys: done.keys };
}

/** The keys' management on the screen: read its statement, take its approval's completion, seal a delete's or a rename's continuation, take a rename's answer. */
export const management = Object.freeze({ read, finish, continuation, renamed });
