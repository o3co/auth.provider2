/**
 * The login screen's pages as the suite's browser meets them: an https front at the screen's origin
 * (the deployment's edge for the screen's distribution) before a server running the screen role. Its
 * authorization page starts the login under PAR and offers two buttons, approve and deny; a start
 * refused, and a decision that does not go through, are sent to a page of their own (`/refused`), so
 * the suite's browser tells them apart by URL. The answer goes to the RP's redirect URI by
 * `form_post` (nextgen's), or by a query (the adaptation's).
 */
import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { type Front, selfSigned, startFront } from "@mod/conformance-front";
import type { LoginScreen, Post, Started, Stopped } from "./screen.ts";
import { stopped } from "./screen.ts";

/** How the answer reaches the RP: nextgen's `form_post`, or the adaptation's query. */
export type Carrying = "form_post" | "query";

/** Where a step of the page was refused, and by whom: the provider's words, or the SDK's, browser's or page's stop. */
export interface Refusal {
	readonly refuser: "provider" | "sdk" | "browser" | "page";
	/** The path or step refused: `/login/start`, `/login/finish`, the SDK's call, `decide`. */
	readonly at: string;
	/** The provider's answer, where it refused. */
	readonly status?: number;
	readonly error?: string;
	readonly description?: string;
	/** The SDK's, the browser's or the page's own word, where one of them stopped. */
	readonly stop?: string;
}

/** What the page saw of each start, by the URL's `request_uri` and `state`: taken, or refused (at the start or after T). */
export type Seen =
	| { readonly kind: "started"; readonly requestUri: string }
	| ({
			readonly kind: "refused";
			readonly requestUri: string | undefined;
			readonly state: string | undefined;
	  } & Refusal);

/** The pages started: their origin, the certificate their front answers with, what they saw, and their stop. */
export interface Pages {
	readonly origin: string;
	readonly certificate: string;
	readonly seen: () => readonly Seen[];
	stop(): Promise<void>;
}

/** How long a start not decided is kept: T's own life is shorter. */
const undecidedMs = 10 * 60_000;

const escaped = (text: string) => text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/** An HTML page, its body as given. */
const page = (title: string, body: string) =>
	`<!doctype html><html><head><meta charset="utf-8"><title>${escaped(title)}</title></head><body>${body}</body></html>`;

/** A stop as the page keeps it. */
const refusalOf = (stop: Stopped): Refusal => {
	if (stop.stopped !== "provider") return { refuser: stop.stopped, at: stop.at, stop: stop.error };
	const body = (stop.body ?? {}) as Record<string, unknown>;
	return {
		refuser: "provider",
		at: stop.at,
		status: stop.status,
		...(typeof body.error === "string" && { error: body.error }),
		...(typeof body.error_description === "string" && { description: body.error_description }),
	};
};

/** The answer to the RP: an auto-submitting form (`form_post`), or a redirect with the fields in its query. */
function carried(
	res: ServerResponse,
	carrying: Carrying,
	redirectUri: string,
	fields: Readonly<Record<string, string>>,
) {
	if (carrying === "query") {
		const target = new URL(redirectUri);
		for (const [name, value] of Object.entries(fields)) target.searchParams.set(name, value);
		res.writeHead(302, { location: target.toString() }).end();
		return;
	}
	const inputs = Object.entries(fields)
		.map(
			([name, value]) => `<input type="hidden" name="${escaped(name)}" value="${escaped(value)}">`,
		)
		.join("");
	res
		.writeHead(200, { "content-type": "text/html; charset=utf-8" })
		.end(
			page(
				"Signing in",
				`<form id="callback" method="post" action="${escaped(redirectUri)}">${inputs}<button id="continue" type="submit">Continue</button></form><script>document.getElementById("callback").submit()</script>`,
			),
		);
}

const formOf = async (req: IncomingMessage) => {
	let text = "";
	for await (const chunk of req) text += chunk;
	return new URLSearchParams(text);
};

/**
 * Starts the pages at `host`, listening on `listen`, the screen role answering them; `post` reaches the
 * issuer, `carrying` says how the answer reaches the RP (read for each answer).
 */
export async function startPages(options: {
	readonly host: string;
	readonly listen: string;
	readonly dir: string;
	readonly screen: () => LoginScreen;
	readonly post: () => Post;
	readonly carrying: () => Carrying;
}): Promise<Pages> {
	const seen: Seen[] = [];
	/** The logins started and not yet decided, by the id their page carries, with what their URL named. */
	const open = new Map<
		string,
		{
			readonly started: Started;
			readonly requestUri: string;
			readonly state: string | undefined;
			readonly at: number;
		}
	>();
	const refused = (
		res: ServerResponse,
		requestUri: string | undefined,
		state: string | undefined,
		refusal: Refusal,
	) => {
		seen.push({ kind: "refused", requestUri, state, ...refusal });
		res.writeHead(302, { location: "/refused" }).end();
	};
	const server = createServer(async (req, res) => {
		try {
			const url = new URL(req.url ?? "/", "http://pages");
			if (req.method === "GET" && url.pathname === "/authorize") {
				for (const [id, held] of open) if (Date.now() - held.at > undecidedMs) open.delete(id);
				const clientId = url.searchParams.get("client_id") ?? undefined;
				const requestUri = url.searchParams.get("request_uri") ?? undefined;
				const state = url.searchParams.get("state") ?? undefined;
				// The URL's values as they came, absent where absent: the provider answers each start.
				const started = await options.screen().startPushed(options.post(), clientId, requestUri);
				if (stopped(started)) return refused(res, requestUri, state, refusalOf(started));
				seen.push({ kind: "started", requestUri: requestUri ?? "" });
				const id = randomUUID();
				open.set(id, { started, requestUri: requestUri ?? "", state, at: Date.now() });
				res
					.writeHead(200, { "content-type": "text/html; charset=utf-8" })
					.end(
						page(
							"Sign in",
							`<form id="decision" method="post" action="/decide"><input type="hidden" name="id" value="${id}"><button id="approve" name="choice" value="approve" type="submit">Approve</button><button id="deny" name="choice" value="deny" type="submit">Deny</button></form>`,
						),
					);
				return;
			}
			if (req.method === "POST" && url.pathname === "/decide") {
				const form = await formOf(req);
				const id = form.get("id") ?? "";
				const held = open.get(id);
				if (held === undefined)
					return refused(res, undefined, undefined, {
						refuser: "page",
						at: "decide",
						stop: "no start open under this id",
					});
				const choice = form.get("choice");
				if (choice !== "approve" && choice !== "deny")
					return refused(res, held.requestUri, held.state, {
						refuser: "page",
						at: "decide",
						stop: "neither approve nor deny",
					});
				open.delete(id);
				const answered =
					choice === "deny"
						? options.screen().deny(held.started)
						: await options.screen().approve(options.post(), held.started);
				if (stopped(answered))
					return refused(res, held.requestUri, held.state, refusalOf(answered));
				const { redirectUri, ...fields } = answered;
				carried(res, options.carrying(), redirectUri, fields);
				return;
			}
			if (req.method === "GET" && url.pathname === "/refused") {
				res
					.writeHead(200, { "content-type": "text/html; charset=utf-8" })
					.end(page("Not signed in", `<p id="refused">This sign-in was refused.</p>`));
				return;
			}
			res.writeHead(404).end();
		} catch (error) {
			if (!res.headersSent)
				res.writeHead(500, { "content-type": "text/plain; charset=utf-8" }).end(String(error));
		}
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const port = (server.address() as AddressInfo).port;
	let edge: Front;
	try {
		const tls = await selfSigned(options.host, join(options.dir, "screen-tls"));
		edge = await startFront({
			upstream: () => `http://127.0.0.1:${port}`,
			publicHost: options.host,
			listen: options.listen,
			tls,
		});
		return {
			origin: edge.origin,
			certificate: tls.cert,
			seen: () => seen,
			stop: async () => {
				await edge.stop();
				await new Promise<void>((resolve) => server.close(() => resolve()));
			},
		};
	} catch (error) {
		await new Promise<void>((resolve) => server.close(() => resolve()));
		throw error;
	}
}
