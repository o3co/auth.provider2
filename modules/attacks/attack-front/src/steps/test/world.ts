import { wireClient } from "@mod/core-wire/testing";
import { wireCertificates } from "@mod/front-relay/testing";
import { registered } from "../../../test/core/clients.ts";
import { type StartedCore, startCore } from "../../../test/core/launch.ts";
import type { PatternSpec } from "../../../test/core/pattern.ts";
import { type Browser, browser } from "../../../test/roles/browser.ts";
import { type RelyingParty, relyingParty } from "../../../test/roles/rp.ts";
import {
	type LoginScreen,
	loginScreen,
	type Started,
	stopped,
} from "../../../test/roles/screen.ts";
import { type BadFront, badFront } from "../../contract.ts";

export const origin = "https://issuer.example";
export const screenOrigin = "https://login.example";
export const provider = {
	issuer: origin,
	tokenUrl: `${origin}/oauth/token`,
	parUrl: `${origin}/oauth/par`,
};

/** A person with a passkey: the browser holding it, the screen they use, the credential's id. */
export interface Person {
	readonly browser: Browser;
	readonly screen: LoginScreen;
	readonly credential: string;
}

/** The worlds started in this process and not stopped: the wire's certificates, one set for the process, are theirs. */
let live = 0;
/** A world's hold on the certificates let go: the last one removes them (counted again after the wait, as another may start). */
async function letGo() {
	live -= 1;
	if (live !== 0) return;
	const certificates = await wireCertificates();
	if (live === 0) await certificates.remove();
}

/**
 * A harness's world: one Core of the default pattern, the relying parties it registers, and a Front
 * per source, each on its own connection (a step is independent: its own subject, client and source).
 */
export async function world(
	clientIds: readonly string[],
	more: Pick<
		PatternSpec,
		"signedClients" | "change" | "seeds" | "outbound" | "released" | "onViolation"
	> & {
		/** More clients the operator registers, beside the relying parties': each as `clients`' `registered` takes it. */
		readonly clients?: readonly unknown[];
	} = {},
) {
	const { clients, ...pattern } = more;
	// Held before the wait, so a last world stopping meanwhile does not remove them under this one.
	live += 1;
	const certificates = await wireCertificates();
	const rps = clientIds.map((id) => relyingParty(provider, id, `https://${id}.example/cb`));
	let core: StartedCore;
	try {
		core = await startCore({
			certificates,
			origin,
			screen: screenOrigin,
			clients: [...(await Promise.all(rps.map((rp) => registered(rp)))), ...(clients ?? [])],
			...pattern,
		});
	} catch (error) {
		await letGo();
		throw error;
	}
	const wires: { close(): void }[] = [];
	let source = 0;
	/** A Front instance's own connection to the Core, as core-wire's test client makes it. */
	const connect = async () => {
		const wire = await wireClient(core.port, certificates);
		wires.push(wire);
		return wire;
	};
	/** A source no other Front of this world declares. */
	const fresh = () => {
		source += 1;
		return `198.51.100.${source}`;
	};
	/** A Front of its own, declaring a source of its own. */
	const front = async (): Promise<BadFront> => badFront(await connect(), fresh());
	// The Core's sealing key as the page pins it: HPKE's raw P-256 point.
	const sealingKey = new Uint8Array([
		4,
		...Buffer.from(core.sealingKey.x ?? "", "base64url"),
		...Buffer.from(core.sealingKey.y ?? "", "base64url"),
	]);
	const screenOf = (b: Browser) => loginScreen({ ring: core.ring, issuer: origin, sealingKey }, b);
	/** A person signed up (F1) through an honest Front, at the RP given, the first of `rps` unless said. */
	const person = async (rp: RelyingParty = rps[0] as RelyingParty): Promise<Person> => {
		const honest = await front();
		const b = browser(screenOrigin);
		const screen = screenOf(b);
		const s = await screen.start(honest, rp.clientId, rp.authorization().jar);
		if (stopped(s)) throw new Error(`a sign-up's start: ${JSON.stringify(s)}`);
		const key = await screen.signUp(honest, s);
		if (stopped(key)) throw new Error(`a sign-up: ${JSON.stringify(key)}`);
		return { browser: b, screen, credential: key.credential };
	};
	/** The token of the first-key mail sent to `to`, as the link's fragment carries it to the page. */
	const firstKeyToken = async (to: string): Promise<string> => {
		const mail = await core.mailWhere((m) => m.purpose === "first-key" && m.to === to);
		return new URL((mail.values as { link: string }).link).hash.slice(1);
	};
	/** An authorization started by a person at an RP, through a Front: the RP's session and the screen's T. */
	const started = async (
		who: Person,
		rp: RelyingParty,
		through: BadFront,
		items: Record<string, unknown> = {},
	) => {
		const session = rp.authorization(items);
		const s = await who.screen.start(through, rp.clientId, session.jar);
		if (stopped(s)) throw new Error(`a start: ${JSON.stringify(s)}`);
		return { session, s: s as Started };
	};
	return {
		core,
		rps,
		sealingKey,
		connect,
		fresh,
		front,
		screenOf,
		person,
		firstKeyToken,
		started,
		stop: async () => {
			for (const wire of wires) wire.close();
			try {
				await core.stop();
			} finally {
				await letGo();
			}
		},
	};
}

export type World = Awaited<ReturnType<typeof world>>;
