import { constants } from "node:fs";
import { open, realpath, stat } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { join, sep } from "node:path";
import { isLoopbackName } from "@mod/url-setting";

/** A server started: the origin it answers at, and its end. */
export interface Serving {
	readonly origin: string;
	close(): Promise<void>;
}

/** What a run writes, its exit code, and the server where it started one. */
export interface Run {
	readonly lines: readonly string[];
	readonly code: number;
	readonly serving?: Serving;
}

const usage: Run = {
	lines: ["usage: publish-serve <directory> <origin> [<reader origin>...]"],
	code: 64,
};

/** The text itself as an origin (`scheme://host[:port]`), with no path, query or trailing `/`. */
const originOf = (text: string) => {
	const url = URL.parse(text);
	return url && url.origin !== "null" && url.origin === text ? url : undefined;
};

/** The address a loopback origin is bound to: an address as written, a name under `localhost` never resolved. */
const addressOf = (url: URL) => {
	const host = url.hostname.startsWith("[") ? url.hostname.slice(1, -1) : url.hostname;
	return /^[0-9.]+$/.test(host) || host.includes(":") ? host : "127.0.0.1";
};

/** Why the arguments are refused, or what they serve. */
async function settingsOf(args: readonly string[]) {
	const [directory, origin, ...readers] = args;
	if (directory === undefined || origin === undefined) return usage;
	const url = originOf(origin);
	if (url?.protocol !== "http:" || !isLoopbackName(url.hostname)) {
		return { lines: [`${origin}: an http origin on a loopback host`], code: 1 };
	}
	const strange = readers.find((r) => !originOf(r));
	if (strange !== undefined) return { lines: [`${strange}: a reader is an origin`], code: 1 };
	const root = await realpath(directory).catch(() => undefined);
	if (!root || !(await stat(root)).isDirectory()) {
		return { lines: [`${directory}: a directory`], code: 1 };
	}
	return { root, url, readers: new Set(readers) };
}

/**
 * The body of the file a path names under the root, or none. Each segment is judged decoded (none
 * `.`, `..`, empty or holding a separator) and names its file as written, as a publisher writes an
 * issuer's percent-encoded path; the trailing `/` dropped. The file is opened, never following a
 * link nor blocking on a FIFO, and read through that one descriptor once it is a regular file
 * whose real path, the same file, is under the root.
 */
async function bodyAt(root: string, path: string): Promise<Buffer | undefined> {
	const segments = path.split("/").slice(1);
	if (segments.at(-1) === "") segments.pop();
	const judged = (segment: string) => {
		try {
			const decoded = decodeURIComponent(segment);
			return !(decoded === "" || decoded === "." || decoded === ".." || /[/\\\0]/.test(decoded));
		} catch {
			return false;
		}
	};
	if (segments.length === 0 || !segments.every(judged)) return undefined;
	const named = join(root, ...segments);
	const file = await open(
		named,
		constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
	).catch(() => undefined);
	if (!file) return undefined;
	try {
		const opened = await file.stat();
		const real = await realpath(named);
		const there = await stat(real);
		const same = opened.ino === there.ino && opened.dev === there.dev;
		if (!opened.isFile() || !same || !real.startsWith(root + sep)) return undefined;
		return await file.readFile();
	} finally {
		await file.close();
	}
}

function answer(root: string, readers: ReadonlySet<string>) {
	const answering = async (request: IncomingMessage, response: ServerResponse) => {
		const origin = request.headers.origin;
		response.setHeader("Vary", "Origin");
		if (origin !== undefined && readers.has(origin)) {
			response.setHeader("Access-Control-Allow-Origin", origin);
		}
		if (request.method !== "GET" && request.method !== "HEAD") {
			response.writeHead(405, { Allow: "GET, HEAD" }).end();
			return;
		}
		const path = (request.url ?? "/").split("?")[0] ?? "/";
		const body = await bodyAt(root, path);
		if (body === undefined) {
			response.writeHead(404).end();
			return;
		}
		response.writeHead(200, {
			"Content-Type": "application/json",
			"Content-Length": body.length,
			"Cache-Control": "no-cache",
		});
		response.end(request.method === "HEAD" ? undefined : body);
	};
	// A file that cannot be read now (gone, denied) is no answer to give: the request is ended, the server serves on.
	return (request: IncomingMessage, response: ServerResponse) => {
		answering(request, response).catch(() => {
			if (!response.headersSent) response.writeHead(404).end();
			else response.destroy();
		});
	};
}

/** Serves a directory's files at an origin on loopback, to the reader origins given (`publish-serve`'s run). */
export async function publishServe(args: readonly string[]): Promise<Run> {
	const settings = await settingsOf(args);
	if ("code" in settings) return settings;
	const { root, url, readers } = settings;
	const server = createServer(answer(root, readers));
	const listening = await new Promise<Error | undefined>((done) => {
		server.once("error", done);
		server.listen(Number(url.port || 80), addressOf(url), () => done(undefined));
	});
	if (listening) return { lines: [`${url.origin}: cannot listen (${listening.message})`], code: 1 };
	const port = (server.address() as AddressInfo).port;
	const origin = url.port === "0" ? `http://${url.hostname}:${port}` : url.origin;
	const serving: Serving = {
		origin,
		close: () =>
			new Promise<void>((closed) => {
				server.closeAllConnections();
				server.close(() => closed());
			}),
	};
	return { lines: [`serving ${root} at ${origin}`], code: 0, serving };
}
