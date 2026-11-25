import { type Approvals, approvals } from "@mod/approvals";
import { assemble, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import type { Keys } from "@mod/keys";
import { keys } from "@mod/keys";
import { type Mail, type Message, mail } from "@mod/mail";
import { passkeyWitnessStandIn } from "@mod/passkey-witness/testing";
import {
	heldKeys,
	type Passkeys,
	passkeyGenerations,
	passkeys,
	type Registrations,
	registrations,
} from "@mod/passkeys";
import promisesModule from "@mod/promises/module";
import { type SubjectRevocation, subjectRevocation } from "@mod/subject-revocation";
import {
	type Transparency,
	type TransparencyLog,
	transparency,
	transparencyLog,
} from "@mod/transparency";
import { type Users, users, type Verified } from "@mod/users";
import { type Ceremonies, ceremonies } from "@mod/webauthn";
import {
	firstKeyNonces,
	firstKeyTokens,
	type StoredNonce,
	type StoredToken,
} from "../../src/contract.ts";
import passkeyManagement from "../../src/module.ts";
import { passkeyManagementConfig } from "../../src/testing.ts";
import { memoryKept } from "./kept.ts";

/** What a composed passkey-management is given in place of its takes. */
export interface Given {
	readonly keys?: Partial<Keys>;
	readonly users?: Partial<Users>;
	readonly passkeys?: Partial<Passkeys>;
	readonly mail?: Mail;
	readonly approvals?: Partial<Approvals>;
	readonly ceremonies?: Partial<Ceremonies>;
	readonly witness?: boolean;
	readonly settings?: Parameters<typeof passkeyManagementConfig>[0];
	readonly modules?: readonly Module[];
}

/** passkey-management composed over stand-ins for what it takes, its stores in memory. */
export async function composed(given: Given = {}) {
	const sent: Message[] = [];
	const none: Verified = { kind: "none" };
	const standIns = defineModule({ name: "stand-ins", replicaSafe: true, takes: [] }, (m) => [
		m.provide(keys).by(() => ({ ...given.keys }) as Keys),
		m.provide(users).by(
			() =>
				({
					byIdentifier: async () => none,
					contactsOf: async () => [],
					bySubject: async () => none,
					...given.users,
				}) as Users,
		),
		m.provide(passkeys).by(() => ({ settle: async () => false, ...given.passkeys }) as Passkeys),
		m.provide(heldKeys).by(() => ({ of: async () => ({ credentials: [], marked: false }) })),
		m.provide(passkeyGenerations).by(() => ({ generation: async () => 0 })),
		m.provide(mail).by(
			() =>
				given.mail ?? {
					send: async (message: Message) => {
						sent.push(message);
						return "sent" as const;
					},
				},
		),
		m.provide(approvals).by(() => ({ ...given.approvals }) as Approvals),
		m
			.provide(ceremonies)
			.by(() => ({ allowsOrigin: () => true, ...given.ceremonies }) as Ceremonies),
		m.provide(registrations).by(() => ({}) as Registrations),
		m.provide(transparency).by(() => ({}) as Transparency),
		m.provide(transparencyLog).by(() => ({ digest: () => "d" }) as unknown as TransparencyLog),
		m
			.provide(subjectRevocation)
			.by(() => ({ check: async () => "valid" }) as unknown as SubjectRevocation),
		m.provide(firstKeyNonces).by(() => memoryKept<StoredNonce>().store),
		m.provide(firstKeyTokens).by(() => memoryKept<StoredToken>().store),
	]);
	const witness = given.witness === false ? [] : [passkeyWitnessStandIn().module];
	const recorded = recordingLog();
	const app = await assemble({
		modules: [passkeyManagement, promisesModule, standIns, ...witness, ...(given.modules ?? [])],
		config: { ...kernelConfig(), ...passkeyManagementConfig(given.settings) },
		runtime: quietRuntime({ log: recorded.log }),
	});
	return { app, sent, recorded };
}
