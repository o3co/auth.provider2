import { clientAllowance } from "@mod/client-allowance";
import { clients } from "@mod/clients";
import { erasers } from "@mod/erasure-extensions";
import { grants, sessionIssuances } from "@mod/grants";
import { issuer } from "@mod/issuer";
import { defineModule, Unavailable } from "@mod/kernel";
import { sessions } from "@mod/session";
import { accessTokens } from "@mod/tokens";
import { type CodeRecord, digestOf, toStored } from "./codes.ts";
import {
	challengeShape,
	codeGrantType,
	codeStore,
	codes,
	redemptionRecords,
	voidList,
} from "./contract.ts";
import { codeGrantEraser } from "./erasure/eraser.ts";
import { portsRefused } from "./erasure/ports.ts";
import { codeGrant } from "./grant.ts";
import { section } from "./section.ts";
import { voiding } from "./voiding/voiding.ts";

const takes = [
	codeStore,
	redemptionRecords,
	voidList,
	sessions,
	clients,
	issuer,
	accessTokens,
	sessionIssuances,
];

// Safe on many instances: every instance runs the sweep over the shared void list, and settling a void twice
// does no harm (voiding/test/voids.test.ts).
export default defineModule({ name: "code-grant", replicaSafe: true, section, takes }, (m) => [
	m.provide(codes).by(async (c) => {
		const store = await c.get(codeStore);
		const opened = await c.get(sessions);
		const known = await c.get(clients);
		const issuerUrl = (await c.get(issuer)).url;
		return {
			issue: async (facts) => {
				if (!challengeShape.test(facts.challenge)) throw new TypeError("code-grant: bad challenge");
				if (facts.root === "") throw new TypeError("code-grant: no root's reference");
				const entry = await opened.entryOf(facts.session);
				// One closed or short since the caller read it is no fault of the caller's: it answers as it can.
				if (entry.kind !== "entered") throw new Unavailable("code-grant");
				const context = entry.session.context;
				if (context.subject !== facts.subject)
					throw new TypeError("code-grant: not this session's subject");
				const client = await known.find(facts.clientId);
				if (
					!client ||
					!clientAllowance.allowsGrant(client, codeGrantType) ||
					!clientAllowance.covers(client, facts, issuerUrl)
				) {
					throw new TypeError("code-grant: outside the client's allowance");
				}
				const code = Buffer.from(c.random.bytes(32)).toString("base64url");
				const { binding, ...rest } = facts;
				const record: CodeRecord = {
					format: 1,
					state: "issued",
					...rest,
					// Its members by name: a binding's further members would make a record no read takes.
					...(binding
						? {
								binding: {
									member: binding.member,
									confirmation: binding.confirmation,
									tokenType: binding.tokenType,
								},
							}
						: {}),
					amr: context.amr,
					authenticatedAt: context.authenticatedAt,
					...(context.authenticatedAtUnknown ? { authenticatedAtUnknown: true } : {}),
				};
				// Created for its subject: one erased here meanwhile gets no code, answered as a session gone.
				const created = await store.create(
					code,
					toStored(record),
					c.section["code-lifetime"] * 1000,
					facts.subject,
				);
				if (created !== "created") throw new Unavailable("code-grant");
				return code;
			},
			digestOf,
			lifetimeMs: () => c.section["code-lifetime"] * 1000,
		};
	}),
	m.contribute(grants).by(async (c) => {
		const issuing = await c.get(accessTokens);
		// A code that comes again must revoke what it gave; without a denylist it could not.
		if (!issuing.revocable()) {
			return c.refuse(
				"code-grant",
				"a configuration that cannot revoke access tokens cannot handle codes",
			);
		}
		// Its tokens are issued from the code's session: unrecorded, a logout could not end them.
		if ((await c.collect(sessionIssuances)).length === 0) {
			return c.refuse(
				"code-grant",
				"its tokens must be recorded to their session, so that a logout ends them",
			);
		}
		const store = await c.get(codeStore);
		const records = await c.get(redemptionRecords);
		const ports = portsRefused({ codes: store, redemptionRecords: records });
		if (ports) return c.refuse("code-grant", ports);
		const voids = voiding({
			store,
			redemptionRecords: records,
			voids: await c.get(voidList),
			tokens: issuing,
			log: c.log,
		});
		c.every(c.section["sweep-interval"] * 1000, () => voids.sweep());
		return codeGrant({
			store,
			redemptionRecords: records,
			sessions: await c.get(sessions),
			settle: voids.settle,
			now: c.clock.now,
		});
	}),
	// Its build takes only its places, collecting no probes: the erasure gate collects erasers.
	m.contribute(erasers).by(async (c) =>
		codeGrantEraser({
			codes: await c.get(codeStore),
			redemptionRecords: await c.get(redemptionRecords),
		}),
	),
]);
