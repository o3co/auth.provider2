import { request } from "node:https";
/** Where a request goes: an origin and the one certificate trusted there (a scene's issuer, or the screen's pages). */
export interface At {
	readonly origin: string;
	readonly certificate: string;
}

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
}

/** A request at an origin, trusting its front's certificate alone. */
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
				headers: {
					...(type === undefined ? {} : { "content-type": type }),
					...(init.origin === undefined ? {} : { origin: init.origin }),
					...init.headers,
				},
			},
			(res) => {
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
		req.end(body);
	});
}
