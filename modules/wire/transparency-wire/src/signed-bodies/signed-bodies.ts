import { z } from "zod";
import {
	base64url,
	coreKinds,
	count,
	digest,
	flow,
	id,
	keyed,
	keySet,
	opIds,
	ordinal,
	v,
	written,
} from "../records/records.ts";
import { bytesOf, isObject, readJson, textOf, unique } from "../text/text.ts";
import { logTyps } from "../words/words.ts";

/** The signer sets held to a count, the generation flow's and the reset instruction's: how many sign, of at least how many keys. */
export const signers = Object.freeze({
	stopInstruction: Object.freeze({ required: 1, least: 1 }),
	restartApproval: Object.freeze({ required: 2, least: 3 }),
	resetInstruction: Object.freeze({ required: 1, least: 1 }),
});

export const publicKey = z
	.object({
		kty: z.enum(["EC", "OKP", "RSA"]),
		crv: z.string().min(1).optional(),
		x: base64url.optional(),
		y: base64url.optional(),
		n: base64url.optional(),
		e: base64url.optional(),
	})
	.strict();

const registration = z.object({ v, registration: id }).strict();
const compactJws = z.string().regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
/** A reset boundary's op from its instruction: `opIds.reset` of the payload's string `id`; none where it has none. */
function resetOpOf(jws: string): string | undefined {
	const bytes = bytesOf(jws.split(".")[1] ?? "");
	const text = bytes && textOf(bytes);
	const read = text === undefined ? undefined : readJson(text);
	const value = read && "value" in read ? read.value : undefined;
	const instructionId = isObject(value) ? value.id : undefined;
	return typeof instructionId === "string" ? opIds.reset(instructionId) : undefined;
}

/** A body that acts on a flow binds it: the flow, the op and the previous position its envelope names. */
const bound = z.object({ v, flow, op: id, prev: count }).strict();
/** A reset boundary's: as `bound`, with the instruction it places (compact) and the version of the set its signature was checked against (`set`). */
const resetBoundary = z
	.object({ v, flow, op: id, prev: count, set: ordinal, instruction: compactJws })
	.strict();
const stopInstruction = z.object({ v, installation: id, generation: ordinal }).strict();
const restartApproval = z
	.object({
		v,
		installation: id,
		ringKey: digest,
		prev: ordinal.optional(),
		from: ordinal.optional(),
		evidence: digest.optional(),
	})
	.strict()
	.refine(
		(a) => [a.prev, a.from, a.evidence].every((f) => (f === undefined) === (a.from === undefined)),
		{
			message:
				"a restart names its previous position, generation and evidence; the install approval none",
		},
	);
export const signerSet = z
	.object({
		v,
		/** Only grows, per purpose: a reader takes no set older than the one it holds. */
		version: ordinal,
		// Every signed object's typ but the callback's proof, which E_sig signs and no set.
		purpose: z.enum(
			Object.keys(logTyps).filter((name) => name !== "callback") as [
				Exclude<keyof typeof logTyps, "callback">,
				...Exclude<keyof typeof logTyps, "callback">[],
			],
		),
		keys: z
			.array(keyed(publicKey))
			.min(1)
			.refine((k) => unique(k, (x) => x.kid), { message: "a kid is named twice" }),
		required: ordinal,
	})
	.strict()
	.refine((s) => s.required <= s.keys.length, { message: "more required than keys" })
	.refine(
		(s) => {
			const held = Object.hasOwn(signers, s.purpose)
				? signers[s.purpose as keyof typeof signers]
				: undefined;
			return !held || (s.required === held.required && s.keys.length >= held.least);
		},
		{ message: "a signer set of a counted purpose is held to its count" },
	);

export const bodies = Object.freeze({
	keySet,
	confirmation: registration,
	denial: registration,
	erasureBoundary: bound,
	resetBoundary,
	tombstone: bound,
	coreRingKey: z.object({ v, kid: id, key: publicKey }).strict(),
	signerSet,
	stopInstruction,
	restartApproval,
});

/** A record no Core writer writes, read with the body its signature verified: the body must match the envelope. */
export const signedRecord = z
	.object({ record: written, body: z.unknown() })
	.strict()
	.superRefine(({ record: r, body }, ctx) => {
		const fail = (message: string) => ctx.addIssue({ code: "custom", message });
		if (coreKinds.includes(r.kind)) return fail("a Core writer's record has no signed body");
		const schema = (bodies as Record<string, z.ZodType>)[r.kind];
		if (!schema) return; // a version's body is its own wire's
		const read = schema.safeParse(body);
		if (!read.success) return fail("the body does not read as its kind's");
		const b = read.data as Record<string, unknown>;
		const prev = r.position - 1;
		if (r.kind === "erasureBoundary" || r.kind === "resetBoundary" || r.kind === "tombstone") {
			const f = b.flow as z.infer<typeof flow>;
			if (f.of !== r.flow.of || f.id !== r.flow.id || b.op !== r.op || b.prev !== prev)
				fail("the body names another flow, op or previous position than its envelope");
		}
		if (r.kind === "resetBoundary" && r.op !== resetOpOf(b.instruction as string))
			fail("a reset boundary's op id is derived from its instruction's id");
		if (r.kind === "stopInstruction" && r.op !== opIds.stop(b.generation as number))
			fail("a stop's op id is derived from the generation it names");
		if (r.kind === "restartApproval" && (b.from === undefined ? r.position !== 1 : b.prev !== prev))
			fail("a restart's body names its previous position; the install approval sits at 1");
	});

export type SignerSet = z.infer<typeof signerSet>;
/** A public key a receiver holds, as a key set carries it. */
export type ReceiverKey = z.infer<typeof publicKey>;
