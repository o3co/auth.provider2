import {
	type ApprovalStore,
	approvalPart,
	approvalStore,
	type approvalStoreNeeds,
	type StoredStatement,
} from "@mod/approvals";
import { defineModule } from "@mod/kernel";
import { recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import type { frameStoreNeeds } from "@mod/transparency";
import { frameParts } from "@mod/transparency-frames";

/** Each need approvals states for its statements, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof approvalStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	confirmedReads: "confirmed-reads",
	authenticated: "authenticated",
};
/** Each need transparency states for the frames, which a part's space declares alike. */
const partGuaranteeFor: Record<keyof typeof frameStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	readsConfirmed: "confirmed-reads",
	authenticated: "authenticated",
};
/** Statements' records by hash: a used one holds the subject and credential its assertion showed. */
const statements: Space = {
	name: "approvals-store.statements",
	guarantees: Object.values(guaranteeFor),
	subjectData: "retained",
};
/** approvals' part of each subject's flow, written by the flow's one write, as the frames are. */
const flows: Space = {
	name: "approvals-store.flows",
	guarantees: Object.values(partGuaranteeFor),
	subjectData: "retained",
};

// Holds nothing of its own, so it is safe on many instances.
export default defineModule({ name: "approvals-store", replicaSafe: true, takes: [store] }, (m) => [
	m.contribute(spaces).by(() => statements),
	m.contribute(spaces).by(() => flows),
	m.contribute(frameParts).by(() => ({ name: approvalPart, space: flows })),
	m.provide(approvalStore).by(async (c): Promise<ApprovalStore> => {
		const place = { store: await c.get(store), space: statements, log: c.log, random: c.random };
		const records = recordsIn<StoredStatement>(place);
		return {
			create: (hash, record, lifetimeMs) => records.create(hash, record, lifetimeMs),
			read: records.read,
			change: (hash, change) => records.change(hash, change),
		};
	}),
]);
