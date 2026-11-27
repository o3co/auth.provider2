import type { AuthorizationItems } from "@mod/sdk-core-wire";
import type { SenderBindings } from "@mod/sender-binding";
import { describe, expect, it } from "vitest";
import type { z } from "zod";
import { codeNeedsOver } from "./code-needs/code-needs.ts";
import type {
	AuthorizationRequests,
	CheckedRequest,
	JarReservations,
	RequestClaims,
	StoredReservation,
	Verified,
} from "./contract.ts";
import { claimsUnread, requestsOver } from "./request/request.ts";
import type { section } from "./section.ts";

export type AuthorizeSettings = z.input<typeof section>;

/** The authorize part of a test's configuration, its screen at a test URL unless set. */
export const authorizeConfig = (settings: Partial<AuthorizeSettings> = {}) => ({
	authorize: { "screen-url": "https://login.example/authorize", ...settings },
});

/**
 * A stand-in for `authorizationRequests`, for a module taking it in its tests: `answer`'s, else the
 * JAR's claims taken as T's items, none of the real check's rules read.
 */
export const authorizationRequestsStandIn = (
	answer?: (verified: Verified) => CheckedRequest,
): AuthorizationRequests => ({
	checked: async (_client, verified) =>
		answer?.(verified) ?? { items: verified.claims as unknown as AuthorizationItems },
});

/**
 * `authorize`'s own check, for a module's test composing it: over the binding kinds and the issuer
 * given, an ID token made unless told, any `claims` refused unless a reader is given, no rule for the
 * audience asked.
 */
export const authorizationRequestsOf = (p: {
	readonly bindings: Pick<SenderBindings, "requestedOf">;
	readonly issuer: string;
	readonly idTokens?: boolean;
	readonly claims?: Pick<RequestClaims, "refusal" | "hint">;
}): AuthorizationRequests =>
	requestsOver({
		needs: codeNeedsOver({
			bindings: p.bindings,
			idTokens: p.idTokens ?? true,
			targets: undefined,
			issuer: p.issuer,
		}),
		claims: p.claims ?? claimsUnread,
	});

/** A place that keeps JAR reservations, as one implementation of the store interface offers it. */
export interface ReservationPlace {
	readonly reservations: JarReservations;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
}

const stored = (n: number) => ({ n }) as unknown as StoredReservation;
const plus = (r: StoredReservation) => ({ value: stored((r as unknown as { n: number }).n + 1) });

/** The contract of the reservations' store interface, run against any implementation. */
export function jarReservationsContract(name: string, open: () => Promise<ReservationPlace>): void {
	describe(`authorize's reservations: ${name}`, () => {
		it("keeps a JAR's first reservation for its lifetime, and no longer", async () => {
			const place = await open();
			expect(await place.reservations.create("c1 j1", stored(1), 1000)).toBe("created");
			expect(await place.reservations.create("c1 j1", stored(2), 1000)).toBe("exists");
			expect(await place.reservations.read("c1 j1")).toEqual(stored(1));
			// A store's clock may run on as the test does: the edges are checked with room either side.
			place.advance(900);
			expect(await place.reservations.read("c1 j1")).toEqual(stored(1));
			place.advance(200);
			expect(await place.reservations.read("c1 j1")).toBeUndefined();
		});

		it("runs two changes at once one after the other, and none where it holds none", async () => {
			const place = await open();
			await place.reservations.create("k", stored(1), 60_000);
			await Promise.all([
				place.reservations.change("k", plus),
				place.reservations.change("k", plus),
			]);
			expect(await place.reservations.read("k")).toEqual(stored(3));
			expect(await place.reservations.change("none", plus)).toBeUndefined();
		});
	});
}
