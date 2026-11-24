import { hpke } from "@mod/sdk-core-wire";
import { concat, utf8 } from "./bytes.ts";

/** The suites this module implements, by the words sdk-core-wire names them in (RFC 9180 §7). */
const kems = { "DHKEM(P-256, HKDF-SHA256)": { id: 0x0010, curve: "P-256", point: 65 } } as const;
const kdfs = { "HKDF-SHA256": { id: 0x0001, length: 32 } } as const;
const aeads = { "AES-128-GCM": { id: 0x0001, key: 16, nonce: 12, tag: 16 } } as const;

const kem = kems[hpke.kem];
const kdf = kdfs[hpke.kdf];
const aead = aeads[hpke.aead];

const i2osp = (n: number, length: number) => {
	const out = new Uint8Array(length);
	for (let i = length - 1, rest = n; i >= 0; i--, rest >>>= 8) out[i] = rest & 0xff;
	return out;
};
const kemSuite = concat(utf8("KEM"), i2osp(kem.id, 2));
const hpkeSuite = concat(utf8("HPKE"), i2osp(kem.id, 2), i2osp(kdf.id, 2), i2osp(aead.id, 2));
const version = utf8("HPKE-v1");
const empty = new Uint8Array();
/** HKDF-Extract's salt where none is given: HashLen zeros, as an HMAC key equal to an empty one. */
const noSalt = new Uint8Array(kdf.length);

async function hmac(key: Uint8Array, data: Uint8Array) {
	const handle = await crypto.subtle.importKey(
		"raw",
		new Uint8Array(key),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	return new Uint8Array(await crypto.subtle.sign("HMAC", handle, new Uint8Array(data)));
}
const labeledExtract = (suite: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array) =>
	hmac(salt.length === 0 ? noSalt : salt, concat(version, suite, utf8(label), ikm));
async function labeledExpand(
	suite: Uint8Array,
	prk: Uint8Array,
	label: string,
	info: Uint8Array,
	length: number,
) {
	const labeled = concat(i2osp(length, 2), version, suite, utf8(label), info);
	const blocks: Uint8Array[] = [];
	for (let i = 1, last = empty; blocks.length * kdf.length < length; i++) {
		last = await hmac(prk, concat(last, labeled, Uint8Array.of(i)));
		blocks.push(last);
	}
	return concat(...blocks).subarray(0, length);
}

/** The key and nonce of a base-mode context, sequence 0 (RFC 9180 §4.1, §5.1). */
async function scheduled(dh: Uint8Array, enc: Uint8Array, pkR: Uint8Array, info: Uint8Array) {
	const eae = await labeledExtract(kemSuite, empty, "eae_prk", dh);
	const shared = await labeledExpand(kemSuite, eae, "shared_secret", concat(enc, pkR), kdf.length);
	const context = concat(
		Uint8Array.of(0),
		await labeledExtract(hpkeSuite, empty, "psk_id_hash", empty),
		await labeledExtract(hpkeSuite, empty, "info_hash", info),
	);
	const secret = await labeledExtract(hpkeSuite, shared, "secret", empty);
	const key = await labeledExpand(hpkeSuite, secret, "key", context, aead.key);
	const nonce = await labeledExpand(hpkeSuite, secret, "base_nonce", context, aead.nonce);
	return {
		key: await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt", "decrypt"]),
		nonce,
	};
}

const ecdh = { name: "ECDH", namedCurve: kem.curve } as const;
/** A public point as an ECDH key; WebCrypto refuses a point off the curve. */
const publicKeyOf = (point: Uint8Array) =>
	crypto.subtle.importKey("raw", new Uint8Array(point), ecdh, true, []);
const pointOf = async (key: CryptoKey) => new Uint8Array(await crypto.subtle.exportKey("raw", key));
const agree = async (privateKey: CryptoKey, publicKey: CryptoKey) =>
	new Uint8Array(
		await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256),
	);

/** What one sealing gives: the sender's encapsulated key (its point) and the ciphertext with its tag. */
export interface Sealed {
	readonly enc: Uint8Array;
	readonly ct: Uint8Array;
}

/** Seals the plaintext to the recipient's point (base mode, sequence 0) under the info and the additional data, with a fresh ephemeral key. */
export async function sealTo(
	recipient: Uint8Array,
	info: Uint8Array,
	aad: Uint8Array,
	plaintext: Uint8Array,
): Promise<Sealed> {
	const ephemeral = await crypto.subtle.generateKey(ecdh, true, ["deriveBits"]);
	return sealToWith(ephemeral, recipient, info, aad, plaintext);
}

/** The same with the ephemeral key given: for a test vector alone, since a key used twice repeats the nonce. */
export async function sealToWith(
	sender: CryptoKeyPair,
	recipient: Uint8Array,
	info: Uint8Array,
	aad: Uint8Array,
	plaintext: Uint8Array,
): Promise<Sealed> {
	const pkR = await publicKeyOf(recipient);
	const enc = await pointOf(sender.publicKey);
	const { key, nonce } = await scheduled(
		await agree(sender.privateKey, pkR),
		enc,
		await pointOf(pkR),
		info,
	);
	const ct = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv: nonce, additionalData: new Uint8Array(aad) },
		key,
		new Uint8Array(plaintext),
	);
	return { enc, ct: new Uint8Array(ct) };
}

/** Opens what was sealed to the recipient's key pair, or none where anything differs. */
export async function openSealed(
	recipient: CryptoKeyPair,
	sealed: Sealed,
	info: Uint8Array,
	aad: Uint8Array,
): Promise<Uint8Array | undefined> {
	if (sealed.enc.length !== kem.point || sealed.ct.length < aead.tag) return undefined;
	try {
		const pkE = await publicKeyOf(sealed.enc);
		const { key, nonce } = await scheduled(
			await agree(recipient.privateKey, pkE),
			sealed.enc,
			await pointOf(recipient.publicKey),
			info,
		);
		const plaintext = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: nonce, additionalData: new Uint8Array(aad) },
			key,
			new Uint8Array(sealed.ct),
		);
		return new Uint8Array(plaintext);
	} catch {
		return undefined;
	}
}
