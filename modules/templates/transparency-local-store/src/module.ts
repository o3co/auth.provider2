import { clientAllowance } from "@mod/client-allowance";
import { clientKeys } from "@mod/client-assertion";
import { type Client, clients } from "@mod/clients";
import { issuer } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import { clientRecords, logStore, type logStoreNeeds, logStoreOver } from "@mod/transparency-local";

/** Each need transparency-local states for its log, as the guarantee the log's space declares. */
const guaranteeFor: Record<keyof typeof logStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	readsConfirmed: "confirmed-reads",
	authenticated: "authenticated",
};
/** Each flow's records, under the flow's words: kept as a log keeps its flows, with no expiry. */
const log: Space = {
	name: "transparency-local-store.log",
	guarantees: Object.values(guaranteeFor),
	subjectData: "retained",
};

// Holds nothing of its own, so it is safe on many instances.
export default defineModule(
	{ name: "transparency-local-store", replicaSafe: true, takes: [store, clients, issuer] },
	(m) => [
		m.contribute(spaces).by(() => log),
		// A client as `clients` holds it: its written keys, and its own ceiling at the issuer.
		m.provide(clientRecords).by(async (c) => {
			const registry = await c.get(clients);
			const { url } = await c.get(issuer);
			return {
				find: registry.find,
				version: (client: Client) => client.version,
				signed: (client: Client) => client.signed === true,
				keys: (client: Client) => client.section(clientKeys).keys,
				ceiling: (client: Client, audience: string, scope: string) =>
					clientAllowance.allowedSelfIssuance(client, scope, [audience], url).kind === "allowed",
			};
		}),
		m.provide(logStore).by(async (c) =>
			logStoreOver({
				store: await c.get(store),
				space: log,
				random: c.random,
				where: "transparency-local-store",
				refuse: (where, reason) => c.refuse(where, reason),
			}),
		),
	],
);
