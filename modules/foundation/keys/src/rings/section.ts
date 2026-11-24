import { z } from "zod";

const kid = z
	.string()
	.regex(/^[A-Za-z0-9._~-]{1,128}$/, "kid is 1 to 128 characters of letters, digits and . _ ~ -");
const alg = z.enum(["EdDSA", "ES256", "PS256", "RS256"]);
export type Alg = z.output<typeof alg>;

const authority = z.strictObject({
	signing: z
		.strictObject({
			kid: kid.describe("The key id tokens signed with this key carry, unique in the section."),
			alg: alg.describe("The algorithm the authority signs with."),
		})
		.describe("The key the authority signs with now."),
	next: z
		.strictObject({
			kid: kid.describe("The key id of the key that signs next, unique in the section."),
			alg: alg.describe("The algorithm the next key will sign with."),
		})
		.optional()
		.describe(
			"The key that signs next: published and verifying now, never signing, so verifiers hold it before it signs.",
		),
	previous: z
		.array(
			z.strictObject({
				kid: kid.describe("The key id of a past signing key, unique in the section."),
				alg: alg.describe("The algorithm the past key signed with."),
				"expires-at": z.iso
					.datetime({ offset: true })
					.describe("When tokens signed by the past key stop being accepted."),
			}),
		)
		.prefault([])
		.describe("Past signing keys that still verify tokens until each one's `expires-at`."),
});

const generation = z.number().int().min(1);

const core = z
	.strictObject({
		generation: generation.describe(
			"The Core generation this Core runs as: its key in `keys` signs, the others verify.",
		),
		keys: z
			.array(
				z.strictObject({
					generation: generation.describe("The Core generation the key is of, one key each."),
					kid: kid.describe("The key id of the generation's key, unique in the section."),
					alg: alg.describe("The algorithm the generation's key signs with."),
				}),
			)
			.min(1)
			.describe(
				"The Core's ring, a key for each Core generation: the screen pins them all, a later one before its generation starts.",
			),
	})
	.superRefine((ring, ctx) => {
		const seen = new Set<number>();
		for (const [i, key] of ring.keys.entries()) {
			if (seen.has(key.generation)) {
				ctx.addIssue({
					code: "custom",
					message: "a generation listed twice",
					path: ["keys", i, "generation"],
				});
			}
			seen.add(key.generation);
		}
		if (!seen.has(ring.generation)) {
			ctx.addIssue({
				code: "custom",
				message: "no key of this generation in keys",
				path: ["generation"],
			});
		}
	});

/** A key the section names: the path of its entry, its kid, and the algorithm of a ring key. */
interface Named {
	readonly at: readonly (string | number)[];
	readonly kid: string;
	readonly alg?: Alg;
}

/** The section's keys, in the order a kid is first named. */
function named(s: Section): Named[] {
	return [
		{ at: ["authority", "signing"], ...s.authority.signing },
		...s.authority.previous.map((p, i) => ({ at: ["authority", "previous", i], ...p })),
		...(s.authority.next ? [{ at: ["authority", "next"], ...s.authority.next }] : []),
		...s.core.keys.map((k, i) => ({ at: ["core", "keys", i], kid: k.kid, alg: k.alg })),
		{ at: ["sealing"], kid: s.sealing.kid },
	];
}

/** The paths of the ring keys' algorithms the section names RS256, which signs and verifies, deprecated. */
export const rs256Named = (s: Section) =>
	named(s)
		.filter((key) => key.alg === "RS256")
		.map((key) => `keys.${[...key.at, "alg"].join(".")}`);

const rings = z.strictObject({
	authority: authority.describe("The authority's ring: its public keys are the JWKS."),
	core: core.describe("The Core's ring: its public keys are what the login screen pins."),
	sealing: z
		.strictObject({
			kid: kid.describe(
				"The key id of the P-256 key the screen seals its requests to, unique in the section.",
			),
		})
		.describe("The Core's sealing key, which the screen pins beside the Core's ring."),
});

export type Section = z.output<typeof rings>;

/** The operator section: the two rings and the sealing key, each kid unique across them, as the holder holds keys by kid. */
export const section = rings.superRefine((s, ctx) => {
	const seen = new Set<string>();
	for (const { kid, at } of named(s)) {
		if (seen.has(kid))
			ctx.addIssue({ code: "custom", message: "duplicate kid", path: [...at, "kid"] });
		seen.add(kid);
	}
});
