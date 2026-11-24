import type { Approval, Completed, Used } from "@mod/approvals";
import type { Client } from "@mod/clients";
import type { CodeFacts } from "@mod/code-grant";
import type { HttpRequest } from "@mod/http";
import { describe, expect, it } from "vitest";
import { type FinishParts, finishing } from "../src/finish/finish.ts";

const now = 1_800_000_000_000;
const issuer = "https://issuer.example";
const iat = now / 1000 - 10;
const statement = `h.${Buffer.from(JSON.stringify({ iat })).toString("base64url")}.s`;
const items = {
	client_id: "c1",
	redirect_uri: "https://rp.example/cb",
	response_type: "code",
	response_mode: "form_post",
	state: "st",
	scope: "read",
	nonce: "n",
	code_challenge: "c".repeat(43),
	code_challenge_method: "S256",
	dpop_jkt: "jkt-1",
	jar_hash: "jh",
} as const;
const client = {
	id: "c1",
	kind: "public",
	method: "none",
	registered: true,
	section: <T>() =>
		({ grants: ["authorization_code"], scopes: ["read"], audiences: ["https://api"] }) as T,
} as Client;

function harness(
	p: {
		used?: Used;
		admitted?: boolean;
		revoked?: boolean;
		completed?: Completed;
		rootCrash?: boolean;
		code_challenge?: string;
		grants?: string[];
		/** Runs just before the code is rooted, as a resend arriving then would. */
		beforeRoot?: () => Promise<void>;
	} = {},
) {
	const log: string[] = [];
	const issued: CodeFacts[] = [];
	let kept: Extract<Completed, { kind: "completed" }> | undefined;
	let published = false;
	const closed: string[] = [];
	let approval: Approval = {
		hash: "t-hash",
		purpose: "authorization",
		items,
		subject: "alice",
		credential: "cred",
		usedAt: now,
		issuedAt: iat * 1000,
	};
	approval = {
		...approval,
		items: { ...items, code_challenge: p.code_challenge ?? items.code_challenge },
	};
	const parts: FinishParts = {
		approvals: {
			use: async () => {
				log.push("use");
				return p.used ?? { kind: "approved", approval };
			},
			completionOf: async () => (published ? kept : undefined),
			publish: async () => {
				log.push("publish");
				published = kept !== undefined;
				return published ? "published" : "unknown";
			},
			complete: async ({ code }) => {
				log.push(`complete ${code}`);
				const answer = p.completed ?? { kind: "completed", enc: "e", ct: "c", record: "r9" };
				if (answer.kind === "completed") {
					kept = answer;
					approval = { ...approval, completed: true };
				}
				return answer;
			},
		},
		clients: {
			find: async (id) => {
				if (id !== "c1") return undefined;
				if (!p.grants) return client;
				const grants = p.grants;
				return {
					...client,
					section: <T>() => ({ grants, scopes: ["read"], audiences: ["https://api"] }) as T,
				} as Client;
			},
		},
		issuance: {
			admits: async (request) => {
				log.push(`admits ${request.grant.subject} ${request.grant.scope.join(" ")}`);
				return p.admitted === false
					? { kind: "refused", policy: "x", reason: "r", description: "no" }
					: { kind: "allowed" };
			},
		},
		sessions: {
			open: async (facts) => {
				log.push(`open ${facts.subject} ${facts.provenSince} ${facts.endsAt}`);
				return p.revoked
					? { kind: "revoked" }
					: { kind: "opened", session: { id: "sess", context: {} as never }, endsAt: facts.endsAt };
			},
			close: async (handle) => {
				closed.push(handle);
				return { kind: "closed" } as never;
			},
		},
		codes: {
			issue: async (facts) => {
				issued.push(facts);
				log.push("issue");
				return `code-${issued.length}`;
			},
			root: async (code, root) => {
				await p.beforeRoot?.();
				log.push(`root ${code} ${root}`);
				if (p.rootCrash) throw new Error("crash");
				return "set";
			},
		},
		bindings: {
			requestedOf: (param) => {
				const jkt = param("dpop_jkt");
				return jkt === undefined
					? { kind: "none" }
					: { kind: "requested", binding: { member: "jkt", confirmation: jkt, tokenType: "DPoP" } };
			},
		},
		issuer,
		delegationS: 3600,
	};
	const finish = finishing(parts);
	const send = async (json: Record<string, unknown> = { statement, assertion: "{}" }) => {
		const r = await finish({ json } as unknown as HttpRequest);
		return { status: r.status, json: (r.body as { json: Record<string, unknown> }).json };
	};
	return { send, log, issued, closed };
}

describe("a login's finish (⑤⑥)", () => {
	it("uses the approval, judges, opens the session, makes a code, completes, and roots the code in the approval's record", async () => {
		const h = harness();
		expect(await h.send()).toEqual({ status: 200, json: { enc: "e", ct: "c" } });
		expect(h.log).toEqual([
			"use",
			"admits alice read",
			`open alice ${iat * 1000} ${iat * 1000 + 3_600_000}`,
			"issue",
			"complete code-1",
			"root code-1 r9",
			"publish",
		]);
		expect(h.issued[0]).toMatchObject({
			clientId: "c1",
			redirectUri: "https://rp.example/cb",
			scope: ["read"],
			audience: ["https://api"],
			session: "sess",
			subject: "alice",
			binding: { member: "jkt", confirmation: "jkt-1", tokenType: "DPoP" },
		});
		expect(h.closed).toEqual([]);
	});

	it("answers a resent finish the completion kept, making no second code", async () => {
		const h = harness();
		const first = await h.send();
		expect(await h.send()).toEqual(first);
		expect(h.issued).toHaveLength(1);
	});

	it("leaves a code unrooted where it falls between completing and rooting: no resend is given it, and none roots it", async () => {
		const h = harness({ rootCrash: true });
		await expect(h.send()).rejects.toThrow("crash");
		expect(h.closed).toEqual(["sess"]);
		// The completion was kept but never went out: a resend is told to ask again, and makes no code.
		expect(await h.send()).toMatchObject({
			status: 503,
			json: { error: "temporarily_unavailable" },
		});
		expect(h.issued).toHaveLength(1);
		expect(h.log.filter((l) => l.startsWith("root"))).toHaveLength(1);
	});

	it("gives a resend arriving between completing and rooting nothing, and the completion only once it went out", async () => {
		let resent: { status: number } | undefined;
		const h = harness({
			beforeRoot: async () => {
				resent = await h.send();
			},
		});
		expect(await h.send()).toEqual({ status: 200, json: { enc: "e", ct: "c" } });
		expect(resent).toMatchObject({ status: 503 });
		expect(h.issued).toHaveLength(1);
		expect(await h.send()).toEqual({ status: 200, json: { enc: "e", ct: "c" } });
	});

	it("opens no session for a client not allowed the code grant, or a malformed challenge", async () => {
		for (const p of [{ grants: [] as string[] }, { code_challenge: "short" }]) {
			const h = harness(p);
			expect(await h.send(), JSON.stringify(p)).toMatchObject({ status: 400 });
			expect(h.log.some((l) => l.startsWith("open"))).toBe(false);
			expect(h.issued).toHaveLength(0);
		}
	});

	it("makes no code where the policies refuse, the person is revoked, or the approval is refused", async () => {
		for (const [p, error] of [
			[{ admitted: false }, "access_denied"],
			[{ revoked: true }, "access_denied"],
			[{ used: { kind: "refused", reason: "used" } }, "invalid_request"],
			[{ used: { kind: "refused", reason: "unverified" } }, "access_denied"],
		] as const) {
			const h = harness(p);
			expect(await h.send(), JSON.stringify(p)).toMatchObject({ status: 400, json: { error } });
			expect(h.issued).toHaveLength(0);
		}
	});

	it("roots no code where the approval is not completed, and closes the session it opened", async () => {
		const h = harness({ completed: { kind: "refused", reason: "ended" } });
		expect(await h.send()).toMatchObject({ status: 400, json: { error: "access_denied" } });
		expect(h.log.some((l) => l.startsWith("root"))).toBe(false);
		expect(h.closed).toEqual(["sess"]);
	});

	it("refuses a finish naming no statement or assertion", async () => {
		const h = harness();
		expect(await h.send({ statement })).toMatchObject({
			status: 400,
			json: { error: "invalid_request" },
		});
		expect(h.log).toEqual([]);
	});
});
