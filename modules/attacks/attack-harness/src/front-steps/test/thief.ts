import { createHash } from "node:crypto";
import { continuations } from "@mod/continuation-wire";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { keys } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig, testHolder } from "@mod/keys/testing";
import { hpke } from "@mod/sdk-core-wire";
import { challengeOf } from "@sdk/login-screen";
import type { Browser } from "../../roles/test/browser.ts";

// The thief's own tools, as a compromised Front drives them: its authenticator and an HPKE sender,
// over what the Front sees (statements are signed, not sealed; the Core's sealing key is public),
// never what only the screen's keys could sign or open.

/** A statement's payload, as anyone reads a compact JWS's middle part. */
export const payloadOf = (compact: string): Record<string, unknown> =>
	JSON.parse(Buffer.from(compact.split(".")[1] ?? "", "base64url").toString("utf8"));

/**
 * A registration response of the thief's own authenticator over the creation the register stage
 * names: the Front reads the creation's options from its statement (signed, not sealed) and asks for
 * a key as a screen would, which only the screen's E_sig could sign the stage for.
 */
export async function thiefBody(thief: Browser, creation: string): Promise<string> {
	const options = (payloadOf(creation).creation as { options: unknown }).options as {
		user_id: string;
		rp_id: string;
		algorithms: number[];
	};
	return thief.create({
		challenge: await challengeOf(creation, "create"),
		rp: { id: options.rp_id, name: "thief" },
		user: { id: Buffer.from(options.user_id, "base64url"), name: "thief", displayName: "thief" },
		pubKeyCredParams: options.algorithms.map((alg) => ({ type: "public-key" as const, alg })),
		excludeCredentials: [],
		authenticatorSelection: { residentKey: "required", userVerification: "required" },
	}).json;
}

/**
 * An assertion of a key the thief made for itself at `rpId`, over the get challenge of a statement the
 * Front saw (a possession's): the right challenge, another key than the one the statement names. With
 * `as`, it names that credential id instead of its own, its signature still the thief's key's.
 */
export async function thiefAssertion(
	thief: Browser,
	statement: string,
	rpId: string,
	as?: string,
): Promise<string> {
	const own = thief.create({
		challenge: new Uint8Array(32),
		rp: { id: rpId, name: "thief" },
		user: { id: new Uint8Array(16), name: "thief", displayName: "thief" },
		pubKeyCredParams: [{ type: "public-key", alg: -7 }],
		excludeCredentials: [],
		authenticatorSelection: { residentKey: "required", userVerification: "required" },
	});
	const made = thief.get({
		challenge: await challengeOf(statement, "get"),
		rpId,
		allowCredentials: [{ type: "public-key", id: Buffer.from(own.id, "base64url") }],
		userVerification: "required",
	});
	if (as === undefined) return made;
	return JSON.stringify({ ...JSON.parse(made), id: as, rawId: as });
}

/**
 * An HPKE sender of the thief's own (keys' `seal`, a standard sealing to any P-256 point): what anyone
 * can seal to the Core's public sealing key. It holds no screen's key and opens nothing sealed to one.
 */
export async function thiefSealer() {
	const app = await assemble({
		modules: [keysModule, testHolder()],
		config: { ...kernelConfig(), ...keysConfig() },
		runtime: quietRuntime(),
	});
	const own = await app.get(keys);
	return {
		seal: (to: Uint8Array, info: string, aad: Uint8Array, plaintext: Uint8Array) =>
			own.seal(to, info, aad, plaintext),
		stop: () => app.stop(1000),
	};
}

const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");

/**
 * A delete's continuation sealed anew by the Front, as anyone can seal to the Core's public sealing
 * key: the stage, statement and sequence it carries (all on the wire, so its additional data is
 * right), another key's id as its body, and its signature by `signer` over continuation-wire's input.
 */
export async function resealedDelete<M extends { statement: string; seq: number }>(
	sealer: Awaited<ReturnType<typeof thiefSealer>>,
	sealingKey: Uint8Array,
	message: M,
	credentialId: string,
	signer: CryptoKey,
): Promise<M & { enc: Uint8Array; ct: Uint8Array }> {
	const h = sha256(message.statement);
	const body = { credential_id: credentialId };
	const bodyHash = sha256(continuations.bodyText("delete", body) ?? "");
	const input = continuations.of("delete", h, message.seq, bodyHash);
	const signature = await crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		signer,
		new TextEncoder().encode(input),
	);
	const plain = continuations.plainOf("delete", body, Buffer.from(signature).toString("base64url"));
	if (plain === undefined) throw new Error("no delete's plaintext");
	const sealed = await sealer.seal(
		sealingKey,
		hpke.info.continuation,
		new TextEncoder().encode(continuations.aad("delete", h, message.seq)),
		new TextEncoder().encode(plain),
	);
	return { ...message, enc: sealed.enc, ct: sealed.ct };
}
