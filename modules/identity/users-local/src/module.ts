import { erasers } from "@mod/erasure-extensions";
import { defineModule, optional, probes } from "@mod/kernel";
import { passkeyWitnesses } from "@mod/passkey-witness";
import { promiseNames, stances } from "@mod/promises";
import { type Space, spaces, store, storeControl } from "@mod/store";
import {
	indexSpaceOf,
	phasedJointRecordsIn,
	phasedRecordsIn,
	subjectRecordsPhase,
} from "@mod/subject-records";
import { ledgers } from "@mod/users";
import { localLedger } from "./ledger.ts";
import {
	type Builders,
	type IdentifierRecord,
	identifierSpace,
	localEraser,
	localMarks,
	localRecords,
	type MarkRecord,
	markSpace,
	placed,
	type SubjectRecord,
	subjectSpace,
} from "./records/records.ts";
import { localWitness } from "./witness.ts";

export default defineModule(
	{
		name: "users-local",
		// It holds nothing in process: its records are behind the store.
		replicaSafe: true,
		takes: [store, optional(storeControl)],
	},
	(m) => [
		m.contribute(spaces).by(() => identifierSpace),
		m.contribute(spaces).by(() => indexSpaceOf(identifierSpace)),
		m.contribute(spaces).by(() => subjectSpace),
		m.contribute(spaces).by(() => indexSpaceOf(subjectSpace)),
		m.contribute(spaces).by(() => markSpace),
		m.contribute(spaces).by(() => indexSpaceOf(markSpace)),
		m.provide(placed).by(async (c): Promise<Builders> => {
			const phase = subjectRecordsPhase.once(await c.getOptional(storeControl));
			const held = await c.get(store);
			const at = (space: Space) => ({
				store: held,
				space,
				index: indexSpaceOf(space),
				log: c.log,
				random: c.random,
			});
			return {
				identifiers: await phasedRecordsIn<IdentifierRecord>(
					at(identifierSpace),
					phase,
					"users-local",
					c.refuse,
				),
				subjects: await phasedRecordsIn<SubjectRecord>(
					at(subjectSpace),
					phase,
					"users-local",
					c.refuse,
				),
				joint: await phasedJointRecordsIn(
					{ identifiers: at(identifierSpace), subjects: at(subjectSpace) },
					phase,
					"users-local",
					c.refuse,
				),
				marks: await phasedRecordsIn<MarkRecord>(at(markSpace), phase, "users-local", c.refuse),
			};
		}),
		m.contribute(ledgers).by(async (c) => localLedger(localRecords(await c.get(placed)), c.random)),
		m.contribute(passkeyWitnesses).by(async (c) => localWitness(localMarks(await c.get(placed)))),
		// Its records and the witness are not apart from the Core's store: a store emptied or rolled back takes them.
		m.contribute(stances).by(() => ({
			promise: promiseNames.storeWrite,
			holds: false,
			by: "users-local",
			reason:
				"its users and its passkey witness's marks are records in the Core's store, the marks beside the passkeys: a store emptied or rolled back takes them unseen, so a subject's identifier may move and a subject holding a passkey reads as holding none",
		})),
		// Its build takes only its records and collects no `probes`, as an eraser's must (erasure-extensions).
		m.contribute(erasers).by(async (c) => localEraser(await c.get(placed))),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const { identifiers, subjects, joint, marks } = await c.get(placed);
			return {
				name: "users-local.phase",
				check: async () => {
					await identifiers.ready();
					await subjects.ready();
					await joint.ready();
					await marks.ready();
				},
			};
		}),
	],
);
