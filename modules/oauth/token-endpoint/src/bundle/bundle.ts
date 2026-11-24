import { createHash } from "node:crypto";
import { clientRules } from "@mod/authority-rules";
import type { HttpRequest } from "@mod/http";
import { isUnavailable, Unavailable } from "@mod/kernel";
import type { Binding } from "@mod/sender-binding";
import type {
	AccessGrant,
	AccessTokenIssuance,
	IssuanceRefused,
	IssuanceRequest,
	Issued,
	IssueLimits,
} from "@mod/tokens";
import type { OperationKind, Stage, Transparency } from "@mod/transparency";
import { type Flow, type Preimage, tokens as receipts } from "@mod/transparency-wire";

/** The token endpoint's kind of operation: a start, then a bundle; one left alone is abandoned, never taken over. */
export const bundleKind: OperationKind = Object.freeze({
	name: "token-endpoint.bundle",
	bundle: true,
	parts: [],
	records: () => [],
	end: () => [],
});

/** What a start record carries of its request, each as sent. */
export type Evidence = Preimage["evidence"];

/**
 * The request's evidence, as it was verified: its DPoP proof where it bound the token by DPoP, and
 * its client's assertion where the client's authentication verified that assertion.
 */
export function evidenceOf(
	request: HttpRequest,
	verified: { readonly binding?: Binding; readonly assertion: boolean },
): Evidence {
	const proof = verified.binding?.tokenType === "DPoP" ? request.headers.get("dpop") : undefined;
	const assertion = verified.assertion ? request.fields.single("client_assertion") : undefined;
	return [
		...(proof ? [{ form: "dpopProof" as const, value: proof }] : []),
		...(assertion ? [{ form: "clientAssertion" as const, value: assertion }] : []),
	];
}

/** The flow a bundle is recorded on: its subject's, a person's, or the client's own. */
export const flowOf = (grant: Pick<AccessGrant, "subject" | "subjectKind">): Flow => ({
	of: grant.subjectKind === "client" ? "client" : "subject",
	id: grant.subject,
});

const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");

/** What bundles are run over. */
export interface BundleParts {
	readonly transparency: Transparency;
	/** A preimage's plaintext digest, as the log's append names it. */
	readonly digest: (preimage: Preimage) => string;
	readonly issuance: Pick<AccessTokenIssuance, "admits" | "prepare" | "sign">;
	/** An op id's ground on a person's flow where the request carries no evidence: fresh each time. */
	readonly fresh: () => string;
	/** Waits before the `look`-th look again at the bundle's judgment. */
	readonly pause: (look: number) => Promise<void>;
	/** How many looks at the bundle's judgment are taken before the issuance is unavailable. */
	readonly looks: number;
}

/** One bundle asked: its access token's request and limits, the request's evidence, its root's reference, its client's registry version. */
export interface BundleAsk {
	readonly request: IssuanceRequest;
	readonly limits: IssueLimits;
	readonly evidence: Evidence;
	readonly root?: string;
	/** The registry version the client's record came from, where its source names one. */
	readonly version?: number;
}

/** A client's own token refused before its op is decided, or once its evidence is found used. */
const refusedFor = (reason: string, description: string): IssuanceRefused => ({
	kind: "refused",
	policy: "token-endpoint",
	reason,
	description,
});
const noEvidence = refusedFor(
	"evidence",
	"a client's own token is issued to a client of a registry version, on its assertion and DPoP proof, one each",
);
const usedEvidence = refusedFor("evidence_used", "the client's assertion or DPoP proof is used");

/** A client's start's op id, its elements and its registry version (V23 OpIdOf, Elems); or why not. */
function clientStartOf(ask: BundleAsk) {
	const read = clientRules.start(ask.evidence, sha256);
	// A client of no registry version has no root a monitor reads: nothing is decided for it.
	if ("refused" in read || ask.version === undefined) return undefined;
	return { op: read.op, named: { registryVersion: ask.version, elements: [...read.elements] } };
}

/**
 * The widest the Core takes a client's evidence's times by (client-assertion's `clock-skew`, dpop's
 * `proof-window`): a start within it took, as the rules' window is wider (transparency-local's
 * `evidence-window`, at least 6m).
 */
const evidenceWindowMs = 5 * 60_000;

/** How many times deciding is tried while the flow is not ready, tending it between. */
const decideTries = 3;

/**
 * Issues one bundle: the policies judge it, its start is recorded, its token prepared with the
 * start's acceptance time as its issue time, the bundle appended once, signed after its receipts,
 * and answered only once taken in as its owner's `took`. Unavailable when the log or the judgment
 * does not come; a refusal after the receipts hands nothing out, the bundle left to be abandoned.
 */
export function bundling(parts: BundleParts) {
	const { transparency } = parts;

	async function decided(flow: Flow, op: string, digest: string) {
		const decide = () => ({ digest, eff: {}, records: [] });
		for (let tried = 0; tried < decideTries; tried++) {
			const answer = await transparency.decide({ kind: bundleKind.name, flow, op, decide });
			if ("prev" in answer) return answer.prev;
			if (answer.refused === "open" || answer.refused === "notReady") await transparency.tend(flow);
			else if (answer.refused !== "moved") break;
		}
		throw new Unavailable("token-endpoint");
	}

	/** The owner's look at its bundle until it is taken in: its own `took` alone answers. */
	async function takenIn(flow: Flow, op: string) {
		for (let look = 0; look < parts.looks; look++) {
			const stepped = await transparency.step({ flow, own: op });
			if ("position" in stepped) {
				if (!stepped.end) continue;
				if (stepped.end.op === op && stepped.end.owner && stepped.end.ending === "took") return;
				break;
			}
			if (stepped.refused === "moved") continue;
			if (!["unjudged", "atHead", "waits"].includes(stepped.refused)) break;
			await parts.pause(look);
		}
		throw new Unavailable("token-endpoint");
	}

	return async (ask: BundleAsk): Promise<Issued> => {
		const admitted = await parts.issuance.admits(ask.request);
		if (admitted.kind === "refused") return admitted;
		const flow = flowOf(ask.request.grant);
		// A client's op is its evidence's, checked before it is decided; a person's, as it was verified.
		const client = flow.of === "client" ? clientStartOf(ask) : undefined;
		if (flow.of === "client" && !client) return noEvidence;
		const ground = () => (ask.evidence.length > 0 ? JSON.stringify(ask.evidence) : parts.fresh());
		const op = client ? client.op : `start:${sha256(ground())}`;
		const root = ask.root === undefined ? {} : { root: ask.root };
		const start: Stage = {
			kind: "start",
			flow,
			op,
			stage: 1,
			last: false,
			...client?.named,
			preimage: {
				v: 1,
				...root,
				evidence: ask.evidence,
				content: client ? { via: "client" } : {},
			},
		};
		const prev = await decided(flow, op, parts.digest(start.preimage));
		const started = await transparency.send({ flow, op, stage: start, prev });
		if ("refused" in started) throw new Unavailable("token-endpoint");
		// Its evidence used: refused for good; its owner does nothing, the op left to its lease's end.
		if (started.answer.result !== "accepted") {
			if (client && started.answer.refusal === "evidenceUsed") return usedEvidence;
			throw new Unavailable("token-endpoint");
		}
		const { acceptedAt, id, position } = started.answer;
		// Its owner closes the op without its bundle: nothing of it is signed.
		const close = () => transparency.rebase({ flow, op, recheck: () => false }).catch(() => {});
		// KE-C02: no bundle after a start that may not have taken by its evidence's times.
		if (client && !clientRules.within(ask.evidence, acceptedAt, evidenceWindowMs)) {
			await close();
			throw new Unavailable("token-endpoint");
		}
		const prepared = await parts.issuance
			.prepare(ask.request, { ...ask.limits, acceptedAt })
			.catch(async (error: unknown) => {
				await close();
				throw error;
			});
		if (prepared.kind === "refused") {
			await close();
			return prepared;
		}
		const digested = receipts.digestInput(prepared.headerText, prepared.claimsText);
		if ("error" in digested)
			throw new TypeError(`token-endpoint: a token's texts: ${digested.error}`);
		// A client's bundle carries its token's texts, for the rules to read its claims.
		const token = { header: prepared.headerText, claims: prepared.claimsText };
		const bundle: Stage = {
			kind: "bundle",
			flow,
			op,
			stage: 2,
			last: true,
			tokens: [{ frame: "accessToken", digest: sha256(digested.input) }],
			preimage: {
				v: 1,
				...root,
				parent: id,
				evidence: [],
				content: client ? { via: "client", token } : {},
			},
		};
		const append = async () => {
			const sent = await transparency.send({ flow, op, stage: bundle, prev: position });
			if ("refused" in sent) throw new Unavailable("token-endpoint");
			if (sent.answer.result === "accepted") return;
			// A client's op, refused, is its lease's end's to leave, unless the refusal closed it.
			if (!client && !sent.end) await close();
			throw new Unavailable("token-endpoint");
		};
		await append();
		const signed = await parts.issuance.sign(prepared).catch(async (error: unknown) => {
			if (!isUnavailable(error)) throw error;
			// Signing fell after the receipts: the same bundle again, the same id and bytes, then signed again.
			await append();
			return parts.issuance.sign(prepared);
		});
		if (signed.kind === "refused") return signed;
		await takenIn(flow, op);
		return signed;
	};
}
