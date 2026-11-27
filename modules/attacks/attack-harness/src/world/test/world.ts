import { wireClient } from "@mod/core-wire/testing";
import type { WireCertificates } from "@mod/front-relay/testing";
import { registered } from "../../pattern/test/clients.ts";
import { type Front, honestRelay, type Wire } from "../../relay/relay.ts";
import { type Browser, browser } from "../../roles/test/browser.ts";
import { type Clock, type RelyingParty, realTime, relyingParty } from "../../roles/test/rp.ts";
import { type LoginScreen, loginScreen, type Started, stopped } from "../../roles/test/screen.ts";

export const origin = "https://issuer.example";
export const screenOrigin = "https://login.example";
export const provider = {
	issuer: origin,
	tokenUrl: `${origin}/oauth/token`,
	parUrl: `${origin}/oauth/par`,
};

/** A key as the Core publishes it: a JWK with its kid. */
type Published = Record<string, string> & { readonly kid: string };

/** A Core started, as a world reaches it: its wire, what the page pins, the mail it sends, and stopping it. */
export interface CoreAt {
	readonly port: number;
	readonly certificates: WireCertificates;
	readonly ring: readonly Published[];
	readonly sealingKey: Published;
	readonly mailWhere: (
		matches: (mail: Record<string, unknown>) => boolean,
	) => Promise<Record<string, unknown>>;
	readonly stop: () => Promise<void>;
}

/** A person with a passkey: the browser holding it, the screen they use, the credential's id. */
export interface Person {
	readonly browser: Browser;
	readonly screen: LoginScreen;
	readonly credential: string;
}

/**
 * The relying parties of `clientIds` and the records an operator registers them by, for a Core to
 * start with; each dating what it signs by the clock given, the real time unless given.
 */
export async function relyingParties(clientIds: readonly string[], clock: Clock = realTime) {
	const rps = clientIds.map((id) => relyingParty(provider, id, `https://${id}.example/cb`, clock));
	return { rps, clients: await Promise.all(rps.map((rp) => registered(rp))) };
}

/**
 * A harness's world on a Core started: the relying parties it registered, and a Front per source made
 * by `make`, each on its own connection (a step is independent: its own subject, client and source).
 * A person signs up through an honest Front of its own.
 */
export function world<F extends Front>(
	core: CoreAt,
	rps: readonly RelyingParty[],
	make: (wire: Wire, source: string) => F,
) {
	const wires: { close(): void }[] = [];
	let source = 0;
	/** A Front instance's own connection to the Core, as core-wire's test client makes it. */
	const connect = async () => {
		const wire = await wireClient(core.port, core.certificates);
		wires.push(wire);
		return wire;
	};
	/** A source no other Front of this world declares. */
	const fresh = () => {
		source += 1;
		return `198.51.100.${source}`;
	};
	/** A Front of its own, declaring a source of its own. */
	const front = async (): Promise<F> => make(await connect(), fresh());
	// The Core's sealing key as the page pins it: HPKE's raw P-256 point.
	const sealingKey = new Uint8Array([
		4,
		...Buffer.from(core.sealingKey.x ?? "", "base64url"),
		...Buffer.from(core.sealingKey.y ?? "", "base64url"),
	]);
	const screenOf = (b: Browser) => loginScreen({ ring: core.ring, issuer: origin, sealingKey }, b);
	/** A person signed up (F1) through an honest Front, at the RP given, the first of `rps` unless said. */
	const person = async (rp: RelyingParty = rps[0] as RelyingParty): Promise<Person> => {
		const honest = honestRelay(await connect(), fresh());
		const b = browser(screenOrigin);
		const screen = screenOf(b);
		const s = await screen.start(honest, rp.clientId, rp.authorization().jar);
		if (stopped(s)) throw new Error(`a sign-up's start: ${JSON.stringify(s)}`);
		const key = await screen.signUp(honest, s);
		if (stopped(key)) throw new Error(`a sign-up: ${JSON.stringify(key)}`);
		return { browser: b, screen, credential: key.credential };
	};
	/** A first-key mail's token, as the link's fragment carries it to the page. */
	const tokenOf = (mail: Record<string, unknown>) =>
		new URL((mail.values as { link: string }).link).hash.slice(1);
	/** The token of the first-key mail sent to `to`, the first of those not `except`, as the link's fragment carries it. */
	const firstKeyToken = async (to: string, except: readonly string[] = []): Promise<string> =>
		tokenOf(
			await core.mailWhere(
				(m) => m.purpose === "first-key" && m.to === to && !except.includes(tokenOf(m)),
			),
		);
	/** An authorization started by a person at an RP, through a Front: the RP's session and the screen's T. */
	const started = async (
		who: Person,
		rp: RelyingParty,
		through: Front,
		items: Record<string, unknown> = {},
	) => {
		const session = rp.authorization(items);
		const s = await who.screen.start(through, rp.clientId, session.jar);
		if (stopped(s)) throw new Error(`a start: ${JSON.stringify(s)}`);
		return { session, s: s as Started };
	};
	return {
		rps,
		sealingKey,
		connect,
		fresh,
		front,
		screenOf,
		person,
		firstKeyToken,
		started,
		/** Closes its connections and stops its Core. */
		stop: async () => {
			for (const wire of wires) wire.close();
			await core.stop();
		},
	};
}

export type World<F extends Front = Front> = ReturnType<typeof world<F>>;
