import { z } from "zod";
import { algorithmNames } from "./keys.ts";

/** An origin as a browser serializes it: https, or http on localhost; a domain, never an IP literal. */
const origin = z.string().refine((entry) => {
	const url = URL.parse(entry);
	if (!url || url.origin !== entry) return false;
	if (url.hostname.startsWith("[") || /^[\d.]+$/.test(url.hostname)) return false;
	return url.protocol === "https:" || (url.protocol === "http:" && url.hostname === "localhost");
}, "a serialized https origin (http only on localhost), on a domain");

/** An Android app origin: the unpadded base64url SHA-256 of its signing certificate; no host. */
const app = /^android:apk-key-hash:[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

/** Whether a browser takes `rpId` on `host`: the host, or a domain above it but no single label. */
const servesHost = (rpId: string, host: string) =>
	host === rpId || (host.endsWith(`.${rpId}`) && rpId.includes("."));

/** A domain's name: lowercase LDH labels of 1 to 63 characters, no hyphen at either end, joined by dots. */
const domain =
	/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

export const section = z
	.strictObject({
		"rp-id": z
			.string()
			// Always a domain (WebAuthn's RP ID is a valid domain string): lowercase LDH labels of 1 to 63
			// characters joined by dots, 253 at most (RFC 1035 §2.3.4), an internationalized one as its
			// A-label (xn--); what the Core signs is sized for no longer.
			.regex(
				domain,
				"a domain: lowercase letters, digits and hyphens in labels of 1 to 63, by dots",
			)
			.max(253)
			.describe(
				"The relying party ID, a domain of 253 characters at most (an internationalized one as its A-label): each web origin's host, or a domain each one lies under.",
			),
		"rp-name": z
			.string()
			.min(1)
			.describe("The relying party's name, as an authenticator shows it."),
		origins: z
			.array(z.union([z.string().regex(app, "an Android app origin of this form"), origin]))
			.min(1)
			.describe(
				"The origins ceremonies may come from, matched exactly: https web origins (http only on localhost, with `kernel.environment = development`), or Android app origins.",
			),
		"top-origins": z
			.array(origin)
			.prefault([])
			.describe(
				"The pages that may frame a ceremony; none by default, so any ceremony in a frame is refused.",
			),
		algorithms: z
			.array(z.enum(algorithmNames))
			.min(1)
			.refine(
				(names) => names.every((name, at) => names.indexOf(name) === at),
				"each algorithm once",
			)
			.prefault(["ES256", "EdDSA"])
			.describe(
				"The algorithms a new passkey may be of, in the order creation offers them: some of ES256, EdDSA and RS256 (RS256 warns at every start). The transparency rules read all three whatever is set.",
			),
	})
	// An entry that is no URL is the origins' own refusal: this never reads one, whether or not zod
	// runs it past a field that failed.
	.refine(
		(s) =>
			s.origins.every(
				(entry) =>
					app.test(entry) ||
					!URL.canParse(entry) ||
					servesHost(s["rp-id"], new URL(entry).hostname),
			),
		{
			path: ["rp-id"],
			message: "the host of each web origin, or a domain each one lies under",
		},
	);

export type Settings = z.output<typeof section>;
