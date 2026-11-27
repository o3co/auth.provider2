/**
 * The word table held to the product: each word's request, sent by a relying party of the harness to
 * a scene, is answered in the table's words and read as the table's row. A word the product changes
 * fails here, rather than reading as no row in a run. The table's refuser is taken as the Core's: the
 * answer comes back through the edge and the Front, which cannot tell who answered.
 */
import { randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type Answered, ask, atIssuer } from "../../scene/test/ask.ts";
import { type Scene, startScene } from "../../scene/test/scene.ts";
import { readingOf, type Word, words } from "../../words/words.ts";
import { type JarChange, type Provider, relyingParty, screenKeys, send } from "./rp.ts";

const screen = "https://login.example.invalid";

/** The scene as generated (JARs pushed alone), and one taking a JAR by value at a login's start too. */
let pushedOnly: Scene | undefined;
let byValue: Scene | undefined;
const started = (scene: Scene | undefined): Scene => {
	if (scene === undefined) throw new Error("the scene did not start");
	return scene;
};
const providerOf = (scene: Scene | undefined): Provider => {
	const { issuer } = started(scene);
	return { issuer, parUrl: `${issuer}/oauth/par`, tokenUrl: `${issuer}/oauth/token` };
};
/** A relying party per scene, registered there and signing for its issuer alone. */
const rpPushed = relyingParty("rp-pushed", "https://rp.example.invalid/cb", () =>
	providerOf(pushedOnly),
);
const rpByValue = relyingParty("rp-by-value", "https://rp.example.invalid/cb", () =>
	providerOf(byValue),
);

/** What a word's request saw beside its answer: whether it carried a DPoP header, and was a start of a request_uri started and taken before. */
interface Driven {
	readonly answer: Answered;
	readonly dpopHeader: boolean;
	readonly startedBefore: boolean;
}
const plain = (answer: Answered): Driven => ({ answer, dpopHeader: false, startedBefore: false });

/** Asks the scene named. */
const at = (scene: Scene | undefined) => {
	const reached = started(scene);
	return (path: string, init: Parameters<typeof ask>[2]) => ask(atIssuer(reached), path, init);
};

/** A JAR changed as `change` says (made when sent, so its times are of then), pushed, proved where `proved`, more fields where given. */
const pushed =
	(change: () => JarChange, proved = false, more: Record<string, string> = {}) =>
	async (): Promise<Driven> => {
		const authorization = rpPushed.authorization(change());
		const { answer } = await send(at(pushedOnly), "/oauth/par", (nonce) => {
			const built = rpPushed.par(authorization, proved ? { nonce } : false);
			return { ...built, form: { ...built.form, ...more } };
		});
		return { answer, dpopHeader: proved, startedBefore: false };
	};

/** A JAR changed as `change` says, sent by value at a login's start, at the scene taking one. */
const startedByValue = (change: () => JarChange) => async (): Promise<Driven> => {
	const { jar } = rpByValue.authorization(change());
	return plain(
		await at(byValue)("/login/start", { method: "POST", json: rpByValue.start({ request: jar }) }),
	);
};

const long = (length: number) => "a".repeat(length);
const seconds = () => Math.floor(Date.now() / 1000);
const nested = { claims: { id_token: { email: { value: null } } } };

/** Each word of the table by its name: the request that should be answered in it. */
const driven: Readonly<Record<string, () => Promise<Driven>>> = {
	"jar-typ-required/par": pushed(() => ({ typ: null })),
	"jar-jti-required/par": pushed(() => ({ drop: ["jti"] })),
	// Past PAR's 90 seconds and within everything else's (an hour; a 60-minute window from nbf).
	"par-jar-lifetime/par": pushed(() => ({ items: { exp: seconds() + 300 } })),
	"jar-dpop-jkt-required/par": pushed(() => ({ drop: ["dpop_jkt"] })),
	"par-dpop-header-only/par": pushed(() => ({ drop: ["dpop_jkt"] }), true),
	"rar-refused/par": pushed(() => ({}), false, { authorization_details: "[]" }),
	"rar-refused/par/claim": pushed(() => ({ items: { authorization_details: [] } })),
	"rar-refused/start/claim": startedByValue(() => ({ items: { authorization_details: [] } })),
	"form-post-required/par": pushed(() => ({ drop: ["response_mode"] })),
	"state-required/par": pushed(() => ({ drop: ["state"] })),
	"nonce-required/par": pushed(() => ({ drop: ["nonce"] })),
	"state-nonce-bound/par/state": pushed(() => ({ items: { state: long(513) } })),
	"state-nonce-bound/par/nonce": pushed(() => ({ items: { nonce: long(513) } })),
	"prompt-none-at-par/par": pushed(() => ({ items: { prompt: "none" } })),
	"claims-null-nested/par": pushed(() => ({ items: nested })),
	"jar-dpop-jkt-required/start": startedByValue(() => ({ drop: ["dpop_jkt"] })),
	"form-post-required/start": startedByValue(() => ({ drop: ["response_mode"] })),
	"state-required/start": startedByValue(() => ({ drop: ["state"] })),
	"nonce-required/start": startedByValue(() => ({ drop: ["nonce"] })),
	"state-nonce-bound/start/state": startedByValue(() => ({ items: { state: long(513) } })),
	"state-nonce-bound/start/nonce": startedByValue(() => ({ items: { nonce: long(513) } })),
	"prompt-none-at-par/start": startedByValue(() => ({ items: { prompt: "none" } })),
	"claims-null-nested/start": startedByValue(() => ({ items: nested })),
	"jar-required/start/neither": async () =>
		plain(await at(pushedOnly)("/login/start", { method: "POST", json: rpPushed.start({}) })),
	"jar-required/start/by-value": async () => {
		const { jar } = rpPushed.authorization();
		return plain(
			await at(pushedOnly)("/login/start", {
				method: "POST",
				json: rpPushed.start({ request: jar }),
			}),
		);
	},
	// A JAR pushed, its request_uri started and taken, then started again under other screen keys.
	"request-uri-once/start": async () => {
		const scene = at(pushedOnly);
		const { answer: push } = await send(scene, "/oauth/par", () =>
			rpPushed.par(rpPushed.authorization()),
		);
		expect(push.status, push.text).toBe(201);
		const requestUri = String(push.json.request_uri);
		const first = await scene("/login/start", {
			method: "POST",
			json: rpPushed.start({ requestUri }, screenKeys()),
		});
		expect(first.status, first.text).toBe(200);
		const again = await scene("/login/start", {
			method: "POST",
			json: rpPushed.start({ requestUri }, screenKeys()),
		});
		return { answer: again, dpopHeader: false, startedBefore: true };
	},
	"rar-refused/token": async () => {
		const authorization = rpPushed.authorization();
		const { answer } = await send(at(pushedOnly), "/oauth/token", (nonce) => {
			const exchange = rpPushed.token(authorization, "no-such-code", nonce);
			return { ...exchange, form: { ...exchange.form, authorization_details: "[]" } };
		});
		return { answer, dpopHeader: true, startedBefore: false };
	},
	// The word alone: a refresh token the provider never issued. That it is the row's (a live family,
	// another key) needs a token issued, which this file does not hold.
	"refresh-dpop-bound/token": async () => {
		const authorization = rpPushed.authorization();
		const made = randomBytes(32).toString("base64url");
		const { answer } = await send(at(pushedOnly), "/oauth/token", (nonce) =>
			rpPushed.refresh(authorization, made, nonce),
		);
		return { answer, dpopHeader: true, startedBefore: false };
	},
};

/** A word's name in this file: its row and place, and what tells it from another of the row's at that place. */
function nameOf(word: Word): string {
	const place = `${word.key}/${word.place}`;
	if (word.key === "state-nonce-bound") return `${place}/${word.description.split(" ")[0]}`;
	if (word.key === "rar-refused" && word.description.startsWith("refused_item"))
		return `${place}/claim`;
	if (word.key === "jar-required")
		return `${place}/${word.description.includes("by value") ? "by-value" : "neither"}`;
	return place;
}

const spec = { host: "localhost", listen: "127.0.0.1", screen } as const;

// One after the other, each held once started, so a start that fails leaves the other to stop.
beforeAll(async () => {
	pushedOnly = await startScene({ ...spec, clients: [rpPushed.registered()] });
	byValue = await startScene({ ...spec, clients: [rpByValue.registered()], byValue: true });
}, 240_000);

afterAll(async () => {
	await Promise.all([pushedOnly?.stop(), byValue?.stop()]);
}, 30_000);

describe("the word table, held to the provider's answers", () => {
	it("has a request for every word, and no name twice", () => {
		const names = words.map(nameOf);
		expect(new Set(names).size).toBe(names.length);
		expect([...names].sort()).toEqual(Object.keys(driven).sort());
	});

	for (const word of words) {
		it(`answers ${nameOf(word)} in the table's words, read as its row`, async () => {
			const drive = driven[nameOf(word)];
			if (drive === undefined) throw new Error(`no request for ${nameOf(word)}`);
			const { answer, dpopHeader, startedBefore } = await drive();
			const said = `${answer.status} ${answer.text}`;
			expect(
				{ error: answer.json.error, description: answer.json.error_description },
				said,
			).toEqual({
				error: word.error,
				description: word.description,
			});
			const reading = readingOf({
				refuser: "core",
				place: word.place,
				error: String(answer.json.error),
				description: String(answer.json.error_description),
				dpopHeader,
				startedBefore,
			});
			expect(reading, said).toEqual(
				word.shared
					? { kind: "unconfirmed", keys: [word.key] }
					: { kind: "observed", key: word.key },
			);
		});
	}
});
