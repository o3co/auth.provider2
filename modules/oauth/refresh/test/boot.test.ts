import { approvals } from "@mod/approvals";
import { claimsSelections } from "@mod/claims-selection";
import { sessionIssuances } from "@mod/grants";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { keys } from "@mod/keys";
import { passkeyChanges, passkeyPart, passkeyStore } from "@mod/passkeys";
import passkeysModule from "@mod/passkeys/module";
import { sessions } from "@mod/session";
import { accessTokens } from "@mod/tokens";
import {
	frameStore,
	operationKinds,
	type StateOwner,
	stateOwners,
	transparencyLog,
} from "@mod/transparency";
import transparencyModule from "@mod/transparency/module";
import { logBook, memoryFrames } from "@mod/transparency/testing";
import { ceremonies } from "@mod/webauthn";
import { expect, it } from "vitest";
import { familiesPart } from "../src/contract.ts";
import refreshModule from "../src/module.ts";
import { familyRecordsInMemory, refreshConfig } from "../src/testing.ts";

/** An owner of fields no module of this composition owns, holding nothing. */
const standIn = (name: string, holds: StateOwner["holds"]): StateOwner => ({
	name,
	holds,
	parts: [name],
	records: () => [{ part: name, name: "state" }],
	read: () => ({}),
	write: () => [undefined],
});

/**
 * refresh beside the real passkeys and transparency, the rest faked: what a whole Core composes of
 * them, so a build that waits on another that waits on it, or a field of the state no owner holds, is
 * seen as the boot's refusal.
 */
const around = defineModule({ name: "around", replicaSafe: true, takes: [] }, (m) => [
	m.provide(frameStore).by(() => memoryFrames([passkeyPart, "approvals", familiesPart]).frames),
	m.provide(transparencyLog).by((c) => logBook(c.clock.now).as("w1")),
	m.provide(passkeyStore).by(() => ({}) as never),
	m.provide(ceremonies).by(() => ({}) as never),
	m.provide(approvals).by(() => ({}) as never),
	m.provide(keys).by(() => ({}) as never),
	m.provide(sessions).by(() => ({}) as never),
	m.provide(accessTokens).by(() => ({}) as never),
	m.provide(claimsSelections).by(() => ({}) as never),
	m.contribute(sessionIssuances).by(() => ({ issued: async () => undefined })),
	// The key change's writer (passkey-management, in a deployment).
	m.contribute(operationKinds).by(() => ({ ...passkeyChanges, bundle: false })),
	// approvals' fields; the families are refresh's.
	m.contribute(stateOwners).by(() => standIn("approvals", ["approvals", "consumed"])),
]);

it("boots beside the real passkeys and transparency: no cycle through passkeys' removals, and the state's families owned", async () => {
	const app = await assemble({
		modules: [
			around,
			familyRecordsInMemory().module,
			transparencyModule,
			passkeysModule,
			refreshModule,
		],
		config: { ...kernelConfig(), ...refreshConfig() },
		runtime: quietRuntime(),
	});
	expect(app).toBeDefined();
});
