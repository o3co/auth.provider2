import { randomBytes } from "node:crypto";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import {
	type PasskeyStore,
	passkeyStore,
	passkeys,
	registrations,
	type StoredCredential,
} from "@mod/passkeys";
import passkeysModule from "@mod/passkeys/module";
import { stances } from "@mod/promises";
import {
	frameStore,
	operationKinds,
	type StateOwner,
	stateOwners,
	transparency,
	transparencyLog,
} from "@mod/transparency";
import transparencyModule from "@mod/transparency/module";
import { logBook, memoryFrames } from "@mod/transparency/testing";
import { ceremonies, freshHandle } from "@mod/webauthn";
import webauthnModule from "@mod/webauthn/module";
import { softwareAuthenticator, testOrigin, webauthnConfig } from "@mod/webauthn/testing";
import { keyChangePart } from "../../contract.ts";
import { keyChangeKind } from "../key-change.ts";

/** Owners of the state's fields passkeys does not hold, each in a record of its own part. */
const otherOwner = (name: string, holds: StateOwner["holds"]): StateOwner => ({
	name,
	holds,
	parts: [name],
	records: () => [{ part: name, name: "state" }],
	read: ([held]) => (held ?? {}) as ReturnType<StateOwner["read"]>,
	write: () => [undefined],
});

/** Credential records in memory. */
function memoryCredentials(): PasskeyStore {
	const kept = new Map<string, StoredCredential>();
	return {
		async create(id, record) {
			if (kept.has(id)) return "exists";
			kept.set(id, structuredClone(record));
			return "created";
		},
		read: async (id) => kept.get(id) && structuredClone(kept.get(id)),
		async change(id, change) {
			const record = kept.get(id);
			if (!record) return undefined;
			const next = change(structuredClone(record));
			if (next) kept.set(id, structuredClone(next.value));
			return { before: record, after: kept.get(id) as StoredCredential };
		},
	};
}

/**
 * passkeys and transparency over memory, the key change's kind registered as this package does, and
 * a first key reserved and verified for a subject, as a registration leaves it before its change.
 */
export async function keyFlow() {
	let clock = 1_000_000;
	const frames = memoryFrames(["passkeys", keyChangePart, "grants", "families"]);
	const book = logBook(() => clock);
	const log = book.as("w1");
	const credentials = memoryCredentials();
	const writer = defineModule({ name: "writer", replicaSafe: true, takes: [] }, (m) => [
		m.provide(frameStore).by(() => frames.frames),
		m.provide(transparencyLog).by(() => log),
		m.provide(passkeyStore).by(() => credentials),
		m.contribute(operationKinds).by(() => keyChangeKind),
		m.contribute(stateOwners).by(() => otherOwner("grants", ["approvals", "consumed"])),
		m.contribute(stateOwners).by(() => otherOwner("families", ["families"])),
		m.contribute(stances).by(() => ({
			promise: "front-compromise-new-authorization",
			holds: true,
			by: "writer",
		})),
	]);
	const app = await assemble({
		modules: [writer, transparencyModule, webauthnModule, passkeysModule],
		config: { ...kernelConfig(), ...webauthnConfig(), passkeys: {} },
		runtime: quietRuntime({ clock: { now: () => clock } }),
	});
	const regs = await app.get(registrations);
	const cer = await app.get(ceremonies);
	const auth = softwareAuthenticator();
	const client = { origin: testOrigin };
	const challenge = () => randomBytes(32).toString("base64url");

	/** A key reserved and verified for `subject`, as `/key/finish` holds it before its change; a first key unless told. */
	const verified = async (subject: string, first = true) => {
		const c = challenge();
		const handle = freshHandle(randomBytes);
		const options = cer.creation(c, { handle, name: subject }, []);
		const attested = await cer.attest(auth.create(options as never, client), c, handle);
		if (attested.kind !== "attested") throw new Error(attested.reason);
		const credential = attested.credential;
		const reserved = await regs.reserve({ subject, credential, first, generation: 0 });
		if (!("reservation" in reserved)) throw new Error(reserved.refused);
		const shown = challenge();
		const response = auth.get(cer.request(shown, [credential]) as never, client, {});
		const v = await regs.verifyPending({ subject, ...reserved, response, challenge: shown });
		if (!("verification" in v)) throw new Error(v.refused);
		return {
			subject,
			reservation: reserved.reservation,
			verification: v.verification,
			credential: credential.id,
			publicKey: credential.publicKey,
			creation: "creation.jws",
			possession: "possession.jws",
			assertion: "{}",
		};
	};
	return {
		frames,
		book,
		log,
		regs,
		verified,
		transparency: await app.get(transparency),
		passkeys: await app.get(passkeys),
		/** Moves the composition's clock and the store's with it. */
		advance: (ms: number) => {
			clock += ms;
			frames.clock.set(frames.clock.now() + ms);
		},
	};
}
