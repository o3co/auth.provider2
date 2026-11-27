import { continuations } from "@mod/continuation-wire";
import { keys } from "@mod/keys";
import { passkeyReset } from "@mod/passkey-reset";
import { heldKeys, passkeys } from "@mod/passkeys";
import { promises } from "@mod/promises";
import { hpke } from "@mod/sdk-core-wire";
import { type Stage, type TransparencyLog, transparencyLog } from "@mod/transparency";
import { holdCertificates } from "../../pattern/test/certificates.ts";
import { startHere } from "../../pattern/test/here.ts";
import { waitingOver } from "../../pattern/test/launch.ts";
import type { PatternSpec, SentMail } from "../../pattern/test/pattern.ts";
import type { Front, Wire } from "../../relay/relay.ts";
import type { Clock } from "../../roles/test/rp.ts";
import { origin, relyingParties, screenOrigin, world } from "../../world/test/world.ts";

/**
 * The harness's Core assembled in the test's own process, for a harness playing a
 * compromised Core: it is handed the Core's powers as ports (writing on its log, opening what was
 * sealed to it), reads of the keys' owner, and an honest operator's reset, never the Core assembled.
 */

/** A test's clock: the real time moved on by what the test advanced, for the Core and the roles alike. */
export interface TestClock {
	readonly now: Clock;
	advance(ms: number): void;
}

export function testClock(): TestClock {
	let ahead = 0;
	return {
		now: () => Date.now() + ahead,
		advance: (ms) => {
			if (!(ms >= 0)) throw new RangeError("a test's clock moves on, never back");
			ahead += ms;
		},
	};
}

/** A flow as the log names it: a subject's or a client's. */
export type Flow = Parameters<TransparencyLog["head"]>[0];

/** A record placed: its id and position; or the log's refusal, by its word. */
export type Placing =
	| { readonly id: string; readonly position: number }
	| { readonly refused: string };

/** A record at a flow's position, as the log holds it: its kind and op, when the log took it (ms), and its judgment, `{verdict, outcome}`. */
export interface AtPosition {
	readonly kind: string;
	readonly op: string;
	readonly acceptedAt: number;
	readonly judged?: { readonly verdict: string; readonly outcome: string };
}

/** The power of a compromised Core's writer on its log: what it places, and what the log holds. */
export interface Writer {
	/** Places a Core writer's record on its flow, after the flow's head where the flow is conditional. */
	place(stage: Stage): Promise<Placing>;
	head(flow: Flow): Promise<number>;
	at(flow: Flow, position: number): Promise<AtPosition | undefined>;
	/** Places a reset instruction (signed by the test, as an embedder's), as the log does. */
	reset(instruction: string): Promise<"placed" | { readonly refused: string }>;
}

/** What a sealed continuation carries, as sent: HPKE's `enc` and the ciphertext, base64url. */
export interface SealedSent {
	readonly enc: string;
	readonly ct: string;
}

/** The power of a compromised Core over what was sealed to it: a continuation opened, its body's text and signature. */
export interface Opener {
	open(
		sealed: SealedSent,
		stage: (typeof continuations.sealed)[number],
		statementHash: string,
		seq: number,
	): Promise<{ readonly body: string; readonly signature: string } | "unopened">;
}

/** What the keys' owner holds, read and never written. */
export interface KeysRead {
	/** A live key's subject and registration; none for a credential no subject holds live. */
	keyOf(
		credential: string,
	): Promise<{ readonly subject: string; readonly registration: string } | undefined>;
	/** A subject's credentials held, and its reservation waiting, where one is. */
	heldBy(subject: string): Promise<{
		readonly credentials: readonly string[];
		/** Its reservation waiting: the key reserved, its COSE_Key in base64url as attested. */
		readonly pending?: {
			readonly reservation: string;
			readonly credential: string;
			readonly publicKey: string;
		};
	}>;
}

/** An honest operator's setup: a reset placed and taken in, as passkey-reset runs it; for a Core composed with it. */
export interface Setup {
	reset(instruction: string): Promise<"placed" | { readonly refused: string }>;
}

/** What a harness's in-process Core is started with: the Core's spec but its wire and origins, the relying parties' ids, its clock. */
export type InProcessSpec = Omit<PatternSpec, "certificates" | "origin" | "screen" | "clients"> & {
	readonly clientIds?: readonly string[];
	/** More clients the operator registers, beside the relying parties'. */
	readonly clients?: readonly unknown[];
};

const bytes = (text: string) => new Uint8Array(Buffer.from(text, "base64url"));
const utf8 = new TextDecoder("utf-8", { fatal: true });
/** A reset's answer in this module's words: placed, or the word it was refused by (the log's refusal, or reset-wire's fault). */
const resetWord = (answer: {
	readonly result: string;
	readonly refusal?: string;
	readonly fault?: string;
}) =>
	answer.result === "accepted"
		? ("placed" as const)
		: { refused: answer.refusal ?? answer.fault ?? answer.result };

/**
 * Starts the harness's Core in this process on `clock`, with the relying parties of `clientIds`: the
 * world on it, its Fronts made by `make`, and the ports. `setup` is there where passkey-reset is
 * composed. `stop` stops it and lets the wire's certificates go.
 */
export async function inProcess<F extends Front>(
	spec: InProcessSpec,
	make: (wire: Wire, source: string) => F,
	clock: TestClock = testClock(),
) {
	const { clientIds, clients, ...pattern } = spec;
	const held = await holdCertificates();
	// The Core once started, stopped where a step after its start fails.
	let started: { stop(withinMs: number): Promise<void> } | undefined;
	try {
		const made = await relyingParties(clientIds ?? [], clock.now);
		const mail: SentMail[] = [];
		const here = await startHere(
			{
				...pattern,
				certificates: held.certificates,
				origin,
				screen: screenOrigin,
				clients: [...made.clients, ...(clients ?? [])],
			},
			(sent) => mail.push(sent),
			{ clock: { now: clock.now } },
		);
		started = here.app;
		const log = here.app.get(transparencyLog);
		const sealing = here.app.get(keys);
		const keysOf = here.app.get(passkeys);
		const heldOf = here.app.get(heldKeys);
		const conditional = (flow: Flow) => flow.of !== "client";
		const writer: Writer = {
			place: async (stage) => {
				const prev = conditional(stage.flow) ? await log.head(stage.flow) : undefined;
				const answer = await log.append(stage, prev);
				return answer.result === "accepted"
					? { id: answer.id, position: answer.position }
					: { refused: answer.refusal };
			},
			head: (flow) => log.head(flow),
			at: async (flow, position) => {
				const placed = await log.at(flow, position);
				if (placed === undefined) return undefined;
				const { kind, op, acceptedAt } = placed.record;
				const judged = placed.finding && {
					verdict: placed.finding.verdict,
					outcome: placed.finding.outcome,
				};
				return judged ? { kind, op, acceptedAt, judged } : { kind, op, acceptedAt };
			},
			reset: async (instruction) => resetWord(await log.reset(instruction)),
		};
		const opener: Opener = {
			open: async (sealed, stage, statementHash, seq) => {
				const aad = new TextEncoder().encode(continuations.aad(stage, statementHash, seq));
				const opened = await sealing.open(
					{ enc: bytes(sealed.enc), ct: bytes(sealed.ct) },
					hpke.info.continuation,
					aad,
				);
				if (opened.kind !== "opened") return "unopened";
				let text: string;
				try {
					text = utf8.decode(opened.plaintext);
				} catch {
					return "unopened";
				}
				const read = continuations.readPlain(stage, text);
				const body = read && continuations.bodyText(stage, read.body);
				return read && body !== undefined ? { body, signature: read.sig } : "unopened";
			},
		};
		const keysRead: KeysRead = {
			keyOf: async (credential) => {
				const key = await keysOf.publicKeyOf(credential);
				return key && { subject: key.subject, registration: key.registration };
			},
			heldBy: async (subject) => {
				const of = await heldOf.of(subject);
				return of.pending
					? {
							credentials: of.credentials,
							pending: {
								reservation: of.pending.reservation,
								credential: of.pending.credential,
								publicKey: of.pending.publicKey,
							},
						}
					: { credentials: of.credentials };
			},
		};
		const composedReset = spec.change?.includes("@mod/passkey-reset") ?? false;
		const setup: Setup | undefined = composedReset
			? {
					reset: async (instruction) =>
						resetWord(await here.app.get(passkeyReset).reset(instruction)),
				}
			: undefined;
		const on = world(
			{
				port: here.port,
				certificates: held.certificates,
				ring: here.ring,
				sealingKey: here.sealingKey,
				metadata: here.metadata,
				mailWhere: waitingOver(mail, "mail"),
				stop: () => here.app.stop(2000),
			},
			made.rps,
			make,
		);
		// What its composition was judged to stand on, at its start: each promise, and whether it holds.
		const judged = here.app
			.get(promises)
			.judgment()
			.map((j) => ({ promise: j.promise as string, held: j.held }));
		return {
			world: on,
			judged,
			writer,
			opener,
			keysRead,
			setup,
			clock,
			/** Stops the world and its Core, and lets the wire's certificates go. */
			stop: async () => {
				try {
					await on.stop();
				} finally {
					await held.letGo();
				}
			},
		};
	} catch (error) {
		try {
			await started?.stop(2000);
		} finally {
			await held.letGo();
		}
		throw error;
	}
}

export type InProcess<F extends Front = Front> = Awaited<ReturnType<typeof inProcess<F>>>;
