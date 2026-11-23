import { z } from "zod";

/** The wire versions a reader of this protocol speaks; a version names one of them. */
const speaks = Object.freeze([1] as const);

/** A client as a registry version holds it: the fields clients reads, its metadata by section. */
const client = z
	.object({
		id: z.string().min(1),
		kind: z.enum(["public", "confidential"]),
		method: z.string().min(1),
		/** Each section's value, held to that section's schema by its owner, not here. */
		sections: z.record(z.string(), z.unknown()),
	})
	.strict();

/**
 * One version of the client registry, as the publisher signs it: the wire's version, a version
 * number that only grows, when it was issued (seconds since the epoch), and every client, each id
 * once.
 */
const version = z
	.object({
		v: z.literal(speaks[0]),
		version: z.number().int().positive(),
		issuedAt: z.number().int().nonnegative(),
		clients: z
			.array(client)
			.refine((clients) => clients.every((c, i) => clients.findIndex((d) => d.id === c.id) === i), {
				message: "a client id is named twice",
			}),
	})
	.strict();

/** The publisher's registry of clients, as a Core reads a version of it and the publisher's tool signs one. */
export const registryWire = Object.freeze({
	/** The type a signed version's header carries. */
	typ: "registry+jwt",
	speaks,
	version,
});

/** A version of the registry, as read. */
export type RegistryVersion = z.infer<typeof version>;
/** A client a version holds. */
export type RegistryClient = z.infer<typeof client>;
