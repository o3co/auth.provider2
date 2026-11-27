import { request } from "node:https";
import type { LookupFunction } from "node:net";
/**
 * Where a request goes: an origin and the one certificate trusted there (a scene's issuer, or the
 * screen's pages); and the address its host is reached at, where this machine has no name for it
 * (the suite's containers' name for this machine).
 */
export interface At {
	readonly origin: string;
	readonly certificate: string;
	readonly address?: string;
}

/** A lookup answering every host with one IPv4 address. */
const onlyAt =
	(address: string): LookupFunction =>
	(_host, options, done) =>
		options.all ? done(null, [{ address, family: 4 }]) : done(null, address, 4);

/** A scene's issuer, as a request reaches it. */
export const atIssuer = (scene: { readonly issuer: string; readonly certificate: string }): At => ({
	origin: scene.issuer,
	certificate: scene.certificate,
});

/** What the scene answered: its status, content type, headers, text, and the text read as JSON where it is. */
export interface Answered {
	readonly status: number;
	readonly type: string;
	readonly headers: Readonly<Record<string, unknown>>;
	readonly text: string;
	readonly json: Record<string, unknown>;
}

/** What a request at the scene carries beside its path: its method, a form or a JSON body, an origin, more headers. */
export interface Asking {
	readonly method?: string;
	readonly form?: Readonly<Record<string, string>>;
	readonly json?: unknown;
	readonly origin?: string;
	readonly headers?: Readonly<Record<string, string>>;
	readonly withinMs?: number;
}

/** How long a request may take, whole, unless the asker says: a scene answers within seconds. */
export const askWithinMs = 60_000;

/** A request at an origin, trusting its front's certificate alone, failed past its time or where its answer is cut off. */
export function ask(at: At, path: string, init: Asking = {}): Promise<Answered> {
	const body =
		init.form !== undefined
			? new URLSearchParams(init.form).toString()
			: init.json !== undefined
				? JSON.stringify(init.json)
				: undefined;
	const type =
		init.form !== undefined
			? "application/x-www-form-urlencoded"
			: init.json !== undefined
				? "application/json"
				: undefined;
	return new Promise((resolve, reject) => {
		const req = request(
			`${at.origin}${path}`,
			{
				method: init.method ?? "GET",
				ca: at.certificate,
				...(at.address === undefined ? {} : { lookup: onlyAt(at.address) }),
				headers: {
					...(type === undefined ? {} : { "content-type": type }),
					...(init.origin === undefined ? {} : { origin: init.origin }),
					...init.headers,
				},
			},
			(res) => {
				res.on("aborted", () => reject(new Error(`${path}: the answer was cut off`)));
				res.on("error", reject);
				let text = "";
				res.on("data", (chunk) => {
					text += chunk;
				});
				res.on("end", () => {
					let json: Record<string, unknown> = {};
					try {
						json = text === "" ? {} : JSON.parse(text);
					} catch {}
					resolve({
						status: res.statusCode ?? 0,
						type: String(res.headers["content-type"] ?? ""),
						headers: res.headers,
						text,
						json,
					});
				});
			},
		);
		req.on("error", reject);
		// Its whole time, however the answer trickles in: a socket's timeout would count only its silences.
		const late = setTimeout(
			() => req.destroy(new Error(`${path}: no answer within its time`)),
			init.withinMs ?? askWithinMs,
		);
		late.unref();
		req.on("close", () => clearTimeout(late));
		req.end(body);
	});
}
