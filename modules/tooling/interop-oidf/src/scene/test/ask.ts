import { request } from "node:https";
import type { Scene } from "./scene.ts";

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

/** A request at the scene's issuer, trusting its front's certificate alone. */
export function ask(scene: Scene, path: string, init: Asking = {}): Promise<Answered> {
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
			`${scene.issuer}${path}`,
			{
				method: init.method ?? "GET",
				ca: scene.certificate,
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
