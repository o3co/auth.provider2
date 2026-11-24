import { clientAssertion } from "@mod/client-assertion";
import { grants } from "@mod/grants";
import { issuer } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { clientCredentials } from "./contract.ts";

export default defineModule(
	{ name: "client-credentials", replicaSafe: true, takes: [issuer, clientAssertion] },
	(m) => [
		m
			.contribute(grants)
			.by(async (c) => clientCredentials((await c.get(issuer)).url, await c.get(clientAssertion))),
	],
);
