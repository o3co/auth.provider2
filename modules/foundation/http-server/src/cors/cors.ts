import type { CorsRule, HttpResponse, Route } from "../contract.ts";

const maxAge = "600";

function varyingByOrigin(headers: Readonly<Record<string, string>>): Record<string, string> {
	const vary = headers.vary;
	return { ...headers, vary: vary ? `${vary}, Origin` : "Origin" };
}

/** A declared route's answer: varies by origin, and lets a listed origin read it. */
export function crossOrigin(
	rule: CorsRule,
	origin: string | undefined,
	origins: ReadonlySet<string>,
	response: HttpResponse,
): HttpResponse {
	const headers = varyingByOrigin(response.headers ?? {});
	if (origin !== undefined && origins.has(origin)) {
		headers["access-control-allow-origin"] = origin;
		if (rule.exposes?.length) headers["access-control-expose-headers"] = rule.exposes.join(", ");
	}
	return { ...response, headers };
}

/** A preflight's answer by a rule, for the methods named: readable only by a listed origin. */
function allowing(
	rule: CorsRule | undefined,
	methods: readonly string[],
	origin: string | undefined,
	origins: ReadonlySet<string>,
): HttpResponse {
	if (!rule || origin === undefined || !origins.has(origin)) {
		return { status: 204, headers: { vary: "Origin" } };
	}
	const headers: Record<string, string> = {
		vary: "Origin",
		"access-control-allow-origin": origin,
		"access-control-allow-methods": methods.join(", "),
		"access-control-max-age": maxAge,
	};
	if (rule.headers?.length) headers["access-control-allow-headers"] = rule.headers.join(", ");
	return { status: 204, headers };
}

/** A preflight's answer where a route of the path takes cross-origin requests; else undefined. */
export function preflight(
	reached: readonly Route[],
	method: string,
	origin: string | undefined,
	origins: ReadonlySet<string>,
): HttpResponse | undefined {
	const declared = reached.filter((r) => r.cors);
	if (declared.length === 0) return undefined;
	const route = declared.find((r) => r.method === (method === "HEAD" ? "GET" : method));
	return allowing(
		route?.cors,
		declared.map((r) => r.method),
		origin,
		origins,
	);
}

/** A preflight's answer for the one method a fallback takes across origins by this rule. */
export function fallbackPreflight(
	rule: CorsRule,
	method: string,
	origin: string | undefined,
	origins: ReadonlySet<string>,
): HttpResponse {
	return allowing(rule, [method], origin, origins);
}
