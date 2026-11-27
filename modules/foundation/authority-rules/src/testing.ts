import { canonicalText } from "@mod/sdk-core-wire";
import { opIds, type Preimage } from "@mod/transparency-wire";
import type { Named } from "./chain/chain.ts";
import { startOf } from "./client/client.ts";
import type { Content } from "./evidence/evidence.ts";

/**
 * A Core writer's records made from evidence given, for a harness that writes on the log as a Core
 * writer would: each kind's fields and preimage laid out as the rules read them, nothing signed here.
 * An honest Core's evidence gives a record the rules take; the same with one thing changed, one they
 * judge by that change.
 */

/** A Core writer's record before its append: the fields it names, its preimage unsealed. */
export type Written = Named & { readonly preimage: Preimage };

/** A screen's continuation as sent: its sequence number, its body's text, its E_sig signature. */
export interface Continued {
	readonly seq: number;
	readonly body: string;
	readonly signature: string;
}

/** A key's ceremony: the creation, the screen's continuation, the possession, the new key's assertion over it. */
export interface Ceremony {
	readonly creation: string;
	readonly continuation: Continued;
	readonly possession: string;
	readonly assertion: string;
	readonly credential: string;
	readonly publicKey: string;
}

/** A live key's approval: its registration's record, the statement it approved, its assertion over it. */
export interface Approved {
	readonly registration: string;
	readonly statement: string;
	readonly assertion: string;
}

type Flow = Named["flow"];
type Tokens = NonNullable<Named["tokens"]>;
type Evidence = Preimage["evidence"];

/**
 * The records, each digest the fields name made by `digest` (SHA-256 in base64url, as the log's). An
 * op is the caller's, in the form the Core's writer gives it; a first key's and a key added's is the
 * reservation its possession names, a client's start's its evidence's.
 */
export function coreRecords(digest: (text: string) => string) {
	const sent = (c: Continued) =>
		canonicalText({ seq: c.seq, body: c.body, signature: c.signature });
	const ceremony = (k: Ceremony): Evidence => [
		{ form: "statement", value: k.creation },
		{ form: "continuation", value: sent(k.continuation) },
		{ form: "statement", value: k.possession },
		{ form: "assertion", value: k.assertion },
	];
	const keyChange = (
		flow: Flow,
		op: string,
		named: NonNullable<Named["keyChange"]>,
		preimage: Preimage,
	): Written => ({ kind: "keyChange", flow, op, stage: 1, last: true, keyChange: named, preimage });
	const ceremonyNamed = (k: Ceremony) => ({
		statement: digest(k.possession),
		evidence: digest(k.assertion),
	});
	return {
		/** A first-trust key, under the reservation its possession names; a sign-up's T first where given. */
		firstKey(flow: Flow, reservation: string, k: Ceremony, signUp?: string): Written {
			const content: Content<"keyChange"> = {
				variant: "first",
				credential: k.credential,
				publicKey: k.publicKey,
			};
			const t: Evidence = signUp === undefined ? [] : [{ form: "statement", value: signUp }];
			return keyChange(flow, reservation, ceremonyNamed(k), {
				v: 1,
				evidence: [...t, ...ceremony(k)],
				content,
			});
		},
		/** A key added by a live key's approval of a passkey-add, under the reservation its possession names. */
		addedKey(flow: Flow, reservation: string, by: Approved, k: Ceremony): Written {
			const content: Content<"keyChange"> = {
				variant: "add",
				credential: k.credential,
				publicKey: k.publicKey,
			};
			return keyChange(flow, reservation, ceremonyNamed(k), {
				v: 1,
				parent: by.registration,
				evidence: [
					{ form: "statement", value: by.statement },
					{ form: "assertion", value: by.assertion },
					...ceremony(k),
				],
				content,
			});
		},
		/** A key deleted by a live key's approval of a passkey-manage and the screen's continuation naming it. */
		deletedKey(
			flow: Flow,
			op: string,
			by: Approved,
			continuation: Continued,
			credential: string,
		): Written {
			const content: Content<"keyChange"> = { variant: "delete", credential };
			const named = { statement: digest(by.statement), evidence: digest(continuation.body) };
			return keyChange(flow, op, named, {
				v: 1,
				parent: by.registration,
				evidence: [
					{ form: "statement", value: by.statement },
					{ form: "assertion", value: by.assertion },
					{ form: "continuation", value: sent(continuation) },
				],
				content,
			});
		},
		/** A live key's approval of T, naming the digest of the code it makes. */
		approval(flow: Flow, op: string, by: Approved, codeDigest: string): Written {
			const content: Content<"approval"> = {};
			return {
				kind: "approval",
				flow,
				op,
				stage: 1,
				last: true,
				approval: {
					statement: digest(by.statement),
					assertion: digest(by.assertion),
					code: codeDigest,
				},
				preimage: {
					v: 1,
					parent: by.registration,
					evidence: [
						{ form: "statement", value: by.statement },
						{ form: "assertion", value: by.assertion },
					],
					content,
				},
			};
		},
		/** A person's start rooted in `root` (an approval, a family), its parent the root, on the request's evidence. */
		start(
			flow: Flow,
			op: string,
			root: string,
			content: Extract<Content<"start">, { via: "code" | "refresh" }>,
			evidence: Evidence = [],
		): Written {
			return {
				kind: "start",
				flow,
				op,
				stage: 1,
				last: false,
				preimage: { v: 1, root, parent: root, evidence, content },
			};
		},
		/** A client's start on its own flow, naming the registry version its record came from: its op and elements derived from its evidence, as the rules derive them; none for evidence of another shape. */
		clientStart(flow: Flow, evidence: Evidence, registryVersion: number): Written | undefined {
			const of = startOf(evidence, digest);
			if ("refused" in of) return undefined;
			const content: Content<"start"> = { via: "client" };
			return {
				kind: "start",
				flow,
				op: of.op,
				stage: 1,
				last: false,
				elements: [...of.elements],
				registryVersion,
				preimage: { v: 1, evidence, content },
			};
		},
		/** A bundle of `op`, its parent its start's record, rooted in `root` where a person's, with its tokens' digests. */
		bundle(
			flow: Flow,
			op: string,
			links: { readonly start: string; readonly root?: string },
			tokens: Tokens,
			content: Content<"bundle">,
		): Written {
			return {
				kind: "bundle",
				flow,
				op,
				stage: 2,
				last: true,
				tokens,
				preimage: {
					v: 1,
					...(links.root === undefined ? {} : { root: links.root }),
					parent: links.start,
					evidence: [],
					content,
				},
			};
		},
		/**
		 * An abandonment of `op`, its `attempt`-th, naming the op's plaintext digest as its intent did
		 * (the caller's: the log keeps it as named and neither it nor these rules check it against the op).
		 */
		abandonment(flow: Flow, op: string, attempt: number, digest: string): Written {
			const content: Content<"abandonment"> = {};
			return {
				kind: "abandonment",
				flow,
				op: opIds.abandonment(op, attempt),
				stage: 1,
				last: true,
				abandons: { op, attempt, digest },
				preimage: { v: 1, evidence: [], content },
			};
		},
	};
}

export type CoreRecords = ReturnType<typeof coreRecords>;
