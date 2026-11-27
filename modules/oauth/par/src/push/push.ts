import { type JarVerifying, jarVerified, type RequestSource } from "@mod/authorize";
import type { Clients } from "@mod/clients";
import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import { Unavailable } from "@mod/kernel";
import type { SenderBindings } from "@mod/sender-binding";
import { z } from "zod";
import type { PushedRequests, StoredPush } from "../contract.ts";

/** Where a client pushes its request. */
export const parPath = "/oauth/par";

/** The prefix of every `request_uri` this provider makes (RFC 9126 §2.2). */
export const requestUriPrefix = "urn:ietf:params:oauth:request_uri:";

/** A pushed request as kept: its client and its JAR's bytes. */
const pushShape = z.object({ client: z.string(), jar: z.string() }).strict();
const pushOf = (kept: StoredPush | undefined) => {
	if (kept === undefined) return undefined;
	const read = pushShape.safeParse(kept);
	if (!read.success) throw new Unavailable("par");
	return read.data;
};

/** What a push takes: what `authorize`'s check of a JAR is made with (the longest life par's own), and its own parts. */
export interface PushParts extends JarVerifying {
	readonly clients: Pick<Clients, "authenticate">;
	readonly bindings: Pick<SenderBindings, "bindingOf" | "requestedOf">;
	readonly pushed: PushedRequests;
	/** How long a pushed request is kept past its JAR's expiry, in seconds. */
	readonly skewS: number;
	readonly token: () => string;
}

const refused = (status: number, error: string, description: string): HttpResponse =>
	jsonAnswer(status, { error, error_description: description });
const bad = (description: string) => refused(400, "invalid_request", description);
const badObject = (description: string) => refused(400, "invalid_request_object", description);

/** The pushed authorization request (RFC 9126): the client authenticated, its JAR verified, kept under a fresh `request_uri`. */
export function pushing(p: PushParts) {
	return async (request: HttpRequest): Promise<HttpResponse> => {
		const field = (name: string) => request.fields.single(name);
		// RFC 6749 §3.1, §3.2: no parameter is sent twice; read first, so none is read as if left out.
		if (request.fields.repeated().length > 0) return bad("repeated parameter");
		// RFC 9126 §2.1: a pushed request names no request_uri; rich authorization requests are not taken.
		if (field("request_uri") !== undefined) return bad("a pushed request names no request_uri");
		if (field("authorization_details") !== undefined)
			return bad("authorization_details are not taken");
		const authenticated = await p.clients.authenticate(request);
		if (authenticated.kind !== "authenticated")
			return refused(401, "invalid_client", "the client is not authenticated");
		const { client } = authenticated;
		const named = field("client_id");
		if (named !== undefined && named !== client.id)
			return bad("client_id is not the authenticated client");
		const jar = field("request");
		if (jar === undefined) return bad("a pushed request carries its JAR in request");
		// The JAR is taken as authorize takes it at its start: one check, authorize's.
		const verified = await jarVerified(p, client, jar);
		if (verified.kind === "refused") return badObject(verified.reason);
		const { claims, exp } = verified;
		// A44: the JAR names the key its tokens are bound to; a proof sent here must be of that key.
		const asked = p.bindings.requestedOf((name) =>
			name === "dpop_jkt" && typeof claims.dpop_jkt === "string" ? claims.dpop_jkt : undefined,
		);
		if (asked.kind === "malformed") return badObject("dpop_jkt is out of its form");
		if (asked.kind !== "requested") return badObject("the request names no dpop_jkt");
		const proved = await p.bindings.bindingOf(request, { kind: "issue" });
		if (proved.kind === "refused") {
			if (proved.unavailable) throw new Unavailable("par");
			// The kind's headers go back with its words: a DPoP nonce asked, for the client to try again.
			const answer = refused(400, proved.error, proved.description ?? "the proof is refused");
			return { ...answer, headers: { ...answer.headers, ...proved.headers } };
		}
		if (proved.kind === "multiple_bindings") return bad("the request proves more than one binding");
		const same = proved.kind === "bound" && proved.binding.member === asked.binding.member;
		if (same && proved.binding.confirmation !== asked.binding.confirmation)
			return refused(400, "invalid_dpop_proof", "the proof is not of the key the request names");
		// Checked again before it is kept: the proof's check may have taken the JAR past its expiry.
		if (exp * 1000 <= p.now()) return badObject("the request has expired");
		const requestUri = `${requestUriPrefix}${p.token()}`;
		const lifetimeMs = (exp + p.skewS) * 1000 - p.now();
		const record = { client: client.id, jar } as unknown as StoredPush;
		// 256 random bits never meet a request_uri kept: one that does is a store that cannot tell.
		if ((await p.pushed.create(requestUri, record, lifetimeMs)) === "exists")
			throw new Unavailable("par");
		const expiresIn = Math.max(1, Math.floor(exp - p.now() / 1000));
		return jsonAnswer(201, { request_uri: requestUri, expires_in: expiresIn });
	};
}

/**
 * The login's start by a pushed request's `request_uri`, contributed to `authorize`: its JAR, for the
 * client that pushed it alone. Many pushes of one JAR meet at the JAR's one start, which `authorize`
 * reserves by client and `jti`.
 */
export const pushedSource = (pushed: PushedRequests, only: boolean): RequestSource => ({
	name: "request_uri",
	only,
	jarOf: async (fields, client) => {
		const uri = fields.requestUri;
		if (uri === undefined) return undefined;
		const kept = uri.startsWith(requestUriPrefix) ? pushOf(await pushed.read(uri)) : undefined;
		if (kept?.client !== client.id)
			return {
				refused: {
					error: "invalid_request_uri",
					description: "the request_uri is unknown, expired or another client's",
				},
			};
		return { jar: kept.jar };
	},
});
