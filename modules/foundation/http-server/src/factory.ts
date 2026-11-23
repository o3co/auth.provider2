import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { guardedRoutes } from "@mod/http/server";
import type { Refusal } from "@mod/kernel";
import type {
	CorsRule,
	HttpRequest,
	HttpResponse,
	HttpServer,
	PolicyMark,
	PolicyRule,
	Route,
} from "./contract.ts";
import { drain, serve } from "./serving/server.ts";

/** What takes the requests no route takes, by their path or by their method, in place of `404` and `405`. */
export interface Fallback {
	/**
	 * The cross-origin rule of a method and path it takes; none where it takes none across origins. The server
	 * answers the preflights of those it names and lets a listed origin read every answer to them, the 500
	 * replacing one it cannot write too, by the section's `cors-origins` and its own rules. It is asked for HEAD
	 * as HEAD, where a declared route reads HEAD as GET. Where it throws, the request is answered as a failure
	 * of the fallback, with no rule settled: nothing to read by across origins, and `answer` never asked.
	 */
	cors?(method: string, path: string): CorsRule | undefined;
	/**
	 * Its answer to a request, whose body is read as a route taking a form, JSON or none would read it;
	 * Unavailable it throws is answered `503`, and any other failure `500`.
	 */
	answer(request: HttpRequest): HttpResponse | Promise<HttpResponse>;
}

/** What an adapter of the http axis builds a server from: what it collected from http's points, and its fallback. */
export interface NodeServerParts {
	/** The routes contributed to http's `routes`. */
	readonly routes: readonly Route[];
	/** The rules contributed to http's `policies`. */
	readonly rules: readonly PolicyRule[];
	/** The marks contributed to http's `marks`. */
	readonly marks: readonly PolicyMark[];
	/** Without it, a path no route reaches is `404`, and a method none of its routes takes `405`. */
	readonly fallback?: Fallback;
}

/** The server to contribute to http's `httpServers`, or the refusals to refuse boot with. */
export type NodeServer =
	| { readonly kind: "server"; readonly server: HttpServer }
	| { readonly kind: "refused"; readonly refusals: readonly Refusal[] };

const keyOf = (route: Route) => `${route.method} ${route.path}`;

/**
 * A server on Node's HTTP over the routes, guarded once by http's `guardedRoutes`; or what those refuse. It
 * serves the routes it guarded, and its start rejects any other routes http hands it.
 */
export function nodeHttpServer(parts: NodeServerParts): NodeServer {
	const checked = guardedRoutes(parts.routes, parts.rules, parts.marks);
	if (checked.kind === "refused") return checked;
	const guarded = new Set(checked.routes.map(keyOf));
	const server: HttpServer = {
		serve: async ({ routes, settings, ends, log, clock }) => {
			const same = routes.length === guarded.size && routes.every((r) => guarded.has(keyOf(r)));
			if (!same) {
				throw new Error(
					"http-server serves only the routes nodeHttpServer guarded at boot, and was handed others",
				);
			}
			const listener = serve({
				routes: checked.routes,
				proxies: settings.proxies,
				origins: settings.origins,
				ends,
				log,
				clock,
				limits: settings.limits,
				...(parts.fallback && { fallback: parts.fallback }),
			});
			listener.listen(settings.port, settings.host);
			await once(listener, "listening");
			return {
				port: (listener.address() as AddressInfo).port,
				drain: (signal) => drain(listener, signal),
			};
		},
	};
	return { kind: "server", server };
}
