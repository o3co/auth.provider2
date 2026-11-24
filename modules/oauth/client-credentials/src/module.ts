import { tokenRules } from "@mod/authority-rules";
import { clientAssertion } from "@mod/client-assertion";
import { grants } from "@mod/grants";
import { issuer } from "@mod/issuer";
import { defineModule, setting } from "@mod/kernel";
import { rateLimit } from "@mod/rate-limit";
import { senderBinding } from "@mod/sender-binding";
import { z } from "zod";
import { clientCredentials, dpopMember } from "./contract.ts";

const section = z.strictObject({
	lifetime: setting
		.duration("s")
		.pipe(
			z
				.number()
				.int()
				.min(60)
				.max(tokenRules.client.lifetimeMs / 1000),
		)
		.prefault("5m")
		.describe(
			"How long a client's own token lives, from 1m to the 15m authority-rules lets one live; written with its unit.",
		),
	requests: z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.prefault(60)
		.describe("The requests a client may make in a minute, counted once it is authenticated."),
	suspended: z
		.array(z.string())
		.prefault([])
		.describe("The clients issued nothing, by id, until removed here; it only narrows."),
});

export default defineModule(
	{
		name: "client-credentials",
		replicaSafe: true,
		section,
		takes: [issuer, clientAssertion, rateLimit, senderBinding],
	},
	(m) => [
		m.contribute(grants).by(async (c) => {
			// Every token it issues is bound by DPoP to the client's key.
			if ((await c.get(senderBinding)).tokenTypeOf(dpopMember) === undefined) {
				return c.refuse(
					"client-credentials",
					"no binding kind writes jkt: compose dpop, which binds the client's token to its key",
				);
			}
			const { lifetime: lifetimeSeconds, requests, suspended } = c.section;
			const counting = await c.get(rateLimit);
			const keys = await c.get(clientAssertion);
			const limits = { lifetimeSeconds, counting, requests, suspended };
			return clientCredentials((await c.get(issuer)).url, keys, limits);
		}),
	],
);
