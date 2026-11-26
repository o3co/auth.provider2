import { expect } from "vitest";
import type { IssueAsk } from "../../src/contract.ts";
import { screenKeys, type world } from "./world.ts";

/** Statements' items and helpers the internal modules' tests share. */
export const items = {
	client_id: "c1",
	redirect_uri: "https://rp.example/cb",
	response_type: "code",
	response_mode: "form_post",
	state: "st",
	scope: "openid",
	nonce: "n",
	code_challenge: "cc",
	code_challenge_method: "S256",
	dpop_jkt: "jkt",
	jar_hash: "jh",
} as const;
export const creationItems = {
	account: "a***@example",
	evidence: "ev",
	ct_hash: "ct",
	subject: "s1",
	kg: 0,
	options: {
		user_id: "u",
		rp_id: "rp.example",
		exclude_credentials: [],
		algorithms: [-7 as const],
	},
};
export const possessionItems = {
	creation_hash: "ch",
	key_jkt: "kZ8n9mX3tQ2vB7cY4wR1sE6uA0pL5dH9jF2gK8hN3oM",
	credential_id: "cred",
	reservation_id: "res",
};

export const payloadOf = (jws: string) =>
	JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8"));

export async function issued(w: Awaited<ReturnType<typeof world>>, ask?: Partial<IssueAsk>) {
	const { screen } = screenKeys();
	const answer = await w.approvals.issue({
		purpose: "authorization",
		items,
		screen,
		by: "src",
		...ask,
	} as IssueAsk);
	if (answer.kind !== "issued") throw new Error(answer.reason);
	return answer;
}

/** A boot refused by approvals for `reason`. */
export const refusal = (reason: RegExp) => ({
	refusals: [
		expect.objectContaining({ where: "approvals", reason: expect.stringMatching(reason) }),
	],
});
