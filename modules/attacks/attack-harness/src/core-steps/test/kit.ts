import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { type Continued, coreRecords } from "@mod/authority-rules/testing";
import { management } from "@sdk/login-screen";
import type { InProcess } from "../../in-process/test/in-process.ts";
import type { Answered, Front, Sent } from "../../relay/relay.ts";
import { browser } from "../../roles/test/browser.ts";
import type { RelyingParty } from "../../roles/test/rp.ts";
import { stopped } from "../../roles/test/screen.ts";
import { type Person, screenOrigin } from "../../world/test/world.ts";

/**
 * What the compromised Core's steps share: the records its bad writer makes (authority-rules'
 * `./testing`, digests SHA-256 as the log's), a Front holding back the requests it names, the
 * evidence a screen's held request leaves unspent, and the request that has the Core take a flow in.
 */

export const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
export const records = coreRecords(sha256);

/** A Front relaying through `through`, keeping each request it is given, and holding back those to `paths`. */
export function holding(through: Front, paths: readonly string[]) {
	const sent: Sent[] = [];
	const held: Sent[] = [];
	const front: Front = {
		post: async (asked): Promise<Answered> => {
			sent.push(asked);
			if (!paths.includes(asked.path)) return through.post(asked);
			held.push(asked);
			// A word the Core never answers: a request held here is never taken for the Core's stall.
			return { status: 599, body: { error: "held_by_front" } };
		},
	};
	return { front, sent, held };
}

/** A signature of the continuation's form (ES256, r||s, base64url) over `input`, by a key no screen holds. */
export function thiefSignature(input: string): string {
	const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	return sign("sha256", Buffer.from(input), {
		key: privateKey,
		dsaEncoding: "ieee-p1363",
	}).toString("base64url");
}

/** The flow of the subject a live credential is held by, and its registration. */
export async function flowOf(core: InProcess, credential: string) {
	const key = await core.keysRead.keyOf(credential);
	if (key === undefined) throw new Error(`no live key ${credential}`);
	return { flow: { of: "subject", id: key.subject } as const, ...key };
}

/**
 * A sealed continuation's evidence, unspent: a passkey-manage approved by `approver` and its sealed
 * `delete` of `target` (or `rename` to `label`) held back before it reached the Core, opened as a
 * compromised Core opens what was sealed to it.
 */
export async function heldSealed(
	core: InProcess,
	who: Person,
	approver: string,
	target: string,
	label?: string,
) {
	const stage = label === undefined ? ("delete" as const) : ("rename" as const);
	const stop = holding(await core.world.front(), ["/continue"]);
	const kept =
		label === undefined
			? await who.screen.deleteKey(stop.front, approver, target)
			: await who.screen.renameKey(stop.front, approver, target, label);
	if (!stopped(kept) || kept.at !== `/continue ${stage}`)
		throw new Error(`${stage}: ${JSON.stringify(kept)}`);
	const finish = stop.sent.find((s) => s.path === "/approval/finish");
	const asked = stop.held[0];
	if (finish === undefined || asked === undefined)
		throw new Error("no approval or continuation sent");
	const statement = finish.body.statement ?? "";
	const opened = await core.opener.open(
		{ enc: asked.body.enc ?? "", ct: asked.body.ct ?? "" },
		stage,
		sha256(statement),
		1,
	);
	if (opened === "unopened") throw new Error(`the ${stage} did not open`);
	const { registration } = await flowOf(core, approver);
	const continuation: Continued = { seq: 1, body: opened.body, signature: opened.signature };
	return {
		by: { registration, statement, assertion: finish.body.assertion ?? "" },
		continuation,
		/** What its screen's E_sig signed: the input a thief's signature of the same form is made over. */
		input: { statement, body: opened.body },
	};
}
export const heldDelete = (core: InProcess, who: Person, approver: string, target: string) =>
	heldSealed(core, who, approver, target);

/**
 * One passkey-manage approved by `approver`, and two continuations of it made by the screen's SDK and
 * sealed to the Core, neither sent: a `rename` of `target` to `label`, and a `delete` of it, each
 * opened as a compromised Core opens what was sealed to it.
 */
export async function heldPair(
	core: InProcess,
	who: Person,
	approver: string,
	target: string,
	label: string,
) {
	const front = holding(await core.world.front(), []);
	const approved = await who.screen.approveManagement(front.front, "passkey-manage", approver);
	if (stopped(approved)) throw new Error(`approval: ${JSON.stringify(approved)}`);
	const finish = front.sent.find((s) => s.path === "/approval/finish");
	if (finish === undefined) throw new Error("no approval sent");
	const statement = approved.manage.compact;
	const sealed = async (stage: "rename" | "delete", body: Record<string, string>) => {
		const made = await management.continuation(approved.manage, stage, 1, body, {
			keys: approved.keys,
			sealingKey: core.world.sealingKey,
		});
		if ("error" in made) throw new Error(`continuation: ${made.error}`);
		const b64u = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
		const opened = await core.opener.open(
			{ enc: b64u(made.sealed.enc), ct: b64u(made.sealed.ct) },
			stage,
			sha256(statement),
			1,
		);
		if (opened === "unopened") throw new Error(`the ${stage} did not open`);
		const continuation: Continued = { seq: 1, body: opened.body, signature: opened.signature };
		return continuation;
	};
	const { registration } = await flowOf(core, approver);
	return {
		by: { registration, statement, assertion: finish.body.assertion ?? "" },
		rename: await sealed("rename", { credential_id: target, label }),
		remove: await sealed("delete", { credential_id: target }),
	};
}

/**
 * A key added's evidence, unspent: a passkey-add approved by `approver`, the new key made on an
 * authenticator of its own and registered, its `/key/finish` held back; the reservation it waits
 * under, and the key reserved, as the keys' owner reads them.
 */
export async function heldAdd(core: InProcess, who: Person, approver: string) {
	const stop = holding(await core.world.front(), ["/key/finish"]);
	const kept = await who.screen.addKey(stop.front, approver, browser(screenOrigin));
	if (!stopped(kept) || kept.at !== "/key/finish") throw new Error(`add: ${JSON.stringify(kept)}`);
	const approval = stop.sent.find((s) => s.path === "/approval/finish");
	const register = stop.sent.find((s) => s.path === "/continue" && s.body.stage === "register");
	const finish = stop.held[0];
	if (approval === undefined || register === undefined || finish === undefined)
		throw new Error("no approval, register or finish sent");
	const { flow, registration } = await flowOf(core, approver);
	const pending = (await core.keysRead.heldBy(flow.id)).pending;
	if (pending === undefined) throw new Error("no reservation waiting");
	return {
		reservation: pending.reservation,
		by: {
			registration,
			statement: approval.body.statement ?? "",
			assertion: approval.body.assertion ?? "",
		},
		ceremony: {
			creation: register.body.statement ?? "",
			continuation: {
				seq: Number(register.body.seq ?? "1"),
				body: register.body.body ?? "",
				signature: register.body.sig ?? "",
			},
			possession: finish.body.statement ?? "",
			assertion: finish.body.assertion ?? "",
			credential: pending.credential,
			publicKey: pending.publicKey,
		},
	};
}

/**
 * A login's approval evidence, unspent: T started by `who` at `rp` and asserted by `credential`, its
 * `/login/finish` held back before it reached the Core. The client its code would be issued to is T's.
 */
export async function heldLogin(
	core: InProcess,
	who: Person,
	rp: RelyingParty,
	credential: string,
) {
	const stop = holding(await core.world.front(), ["/login/finish"]);
	const { s } = await core.world.started(who, rp, stop.front);
	const kept = await who.screen.approve(stop.front, s, [credential]);
	if (!stopped(kept) || kept.at !== "/login/finish")
		throw new Error(`login: ${JSON.stringify(kept)}`);
	const finish = stop.held[0];
	if (finish === undefined) throw new Error("no finish sent");
	const { registration } = await flowOf(core, credential);
	const statement = finish.body.statement ?? "";
	return {
		by: { registration, statement, assertion: finish.body.assertion ?? "" },
		client: rp.clientId,
		/** The approval's op as the Core's writer names it. */
		op: `approval:${sha256(statement)}`,
	};
}

/** A token's digest, as a bundle names it: any one, made of `seed`. */
export const tokenDigest = (seed: string) => sha256(`token:${seed}`);

/**
 * A new login by `who` at `rp`, through an honest Front: its finish has the Core take the subject's
 * flow in; the stop, where the Core refused it.
 */
export async function loginProbe(core: InProcess, who: Person, rp: RelyingParty) {
	const front = await core.world.front();
	const { s } = await core.world.started(who, rp, front);
	return who.screen.approve(front, s, [who.credential]);
}

/** The wire's refusal word of a stop at the Core; none for any other answer. */
export const refusalOf = (stop: object | string): string | undefined =>
	stopped(stop) && "answered" in stop && stop.stopped === "core"
		? (stop.answered.body as { error?: string } | undefined)?.error
		: undefined;
