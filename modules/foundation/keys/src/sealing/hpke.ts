import { createCipheriv, createDecipheriv, createECDH, createHmac, ECDH } from "node:crypto";
import { hpke } from "@mod/sdk-core-wire";

/** The suites this module implements, by the words sdk-core-wire names them in (RFC 9180 §7). */
const kems = {
	"DHKEM(P-256, HKDF-SHA256)": { id: 0x0010, curve: "prime256v1", secret: 32, point: 65 },
} as const;
const kdfs = { "HKDF-SHA256": { id: 0x0001, hash: "sha256", length: 32 } } as const;
const aeads = {
	"AES-128-GCM": { id: 0x0001, cipher: "aes-128-gcm", key: 16, nonce: 12, tag: 16 },
} as const;

const kem = kems[hpke.kem];
const kdf = kdfs[hpke.kdf];
const aead = aeads[hpke.aead];

/** P-256's group order: a derived secret is below it and above 0. */
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const encoder = new TextEncoder();
const i2osp = (n: number, length: number) => {
	const out = new Uint8Array(length);
	for (let i = length - 1, rest = n; i >= 0; i--, rest >>>= 8) out[i] = rest & 0xff;
	return out;
};
const joined = (...parts: readonly Uint8Array[]) => new Uint8Array(Buffer.concat(parts));

const kemSuite = joined(encoder.encode("KEM"), i2osp(kem.id, 2));
const hpkeSuite = joined(
	encoder.encode("HPKE"),
	i2osp(kem.id, 2),
	i2osp(kdf.id, 2),
	i2osp(aead.id, 2),
);
const version = encoder.encode("HPKE-v1");
const empty = new Uint8Array();

const hmac = (key: Uint8Array, data: Uint8Array) =>
	new Uint8Array(createHmac(kdf.hash, key).update(data).digest());
const labeledExtract = (suite: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array) =>
	hmac(salt, joined(version, suite, encoder.encode(label), ikm));
function labeledExpand(
	suite: Uint8Array,
	prk: Uint8Array,
	label: string,
	info: Uint8Array,
	length: number,
) {
	const labeled = joined(i2osp(length, 2), version, suite, encoder.encode(label), info);
	const blocks: Uint8Array[] = [];
	for (let i = 1, last = empty; blocks.length * kdf.length < length; i++) {
		last = hmac(prk, joined(last, labeled, Uint8Array.of(i)));
		blocks.push(last);
	}
	return joined(...blocks).subarray(0, length);
}

/** The key pair DeriveKeyPair makes of the input keying material (RFC 9180 §7.1.3): its secret and its point. */
export function derivedKeyPair(ikm: Uint8Array): {
	readonly secret: Uint8Array;
	readonly point: Uint8Array;
} {
	const prk = labeledExtract(kemSuite, empty, "dkp_prk", ikm);
	for (let counter = 0; counter < 256; counter++) {
		const secret = labeledExpand(kemSuite, prk, "candidate", i2osp(counter, 1), kem.secret);
		const value = BigInt(`0x${Buffer.from(secret).toString("hex")}`);
		if (value === 0n || value >= order) continue;
		const ecdh = createECDH(kem.curve);
		ecdh.setPrivateKey(secret);
		return { secret, point: new Uint8Array(ecdh.getPublicKey()) };
	}
	throw new Error("hpke: no key pair derived");
}

/** Whether `point` is a point of the curve, written uncompressed. */
export function onCurve(point: Uint8Array): boolean {
	if (point.length !== kem.point || point[0] !== 4) return false;
	try {
		ECDH.convertKey(point, kem.curve, undefined, undefined, "uncompressed");
		return true;
	} catch {
		return false;
	}
}

/** The AEAD's key and nonce for one sealing, from the KEM's shared secret (RFC 9180 §4.1, §5.1, base mode). */
function scheduled(dh: Uint8Array, enc: Uint8Array, pkR: Uint8Array, info: Uint8Array) {
	const eae = labeledExtract(kemSuite, empty, "eae_prk", dh);
	const shared = labeledExpand(kemSuite, eae, "shared_secret", joined(enc, pkR), kdf.length);
	const context = joined(
		Uint8Array.of(0),
		labeledExtract(hpkeSuite, empty, "psk_id_hash", empty),
		labeledExtract(hpkeSuite, empty, "info_hash", info),
	);
	const secret = labeledExtract(hpkeSuite, shared, "secret", empty);
	return {
		key: labeledExpand(hpkeSuite, secret, "key", context, aead.key),
		nonce: labeledExpand(hpkeSuite, secret, "base_nonce", context, aead.nonce),
	};
}

/** What one sealing gives: the sender's encapsulated key and the ciphertext with its tag. */
export interface Sealing {
	readonly enc: Uint8Array;
	readonly ct: Uint8Array;
}

/**
 * Seals `plaintext` once to the recipient's point (`pkR`, uncompressed), under a sender key derived
 * from `ikm`, fresh random bytes the caller draws. Throws a TypeError for what is no P-256 point.
 */
export function sealTo(
	pkR: Uint8Array,
	info: Uint8Array,
	aad: Uint8Array,
	plaintext: Uint8Array,
	ikm: Uint8Array,
): Sealing {
	if (!onCurve(pkR)) throw new TypeError("keys: what is sealed to is no P-256 point");
	const sender = derivedKeyPair(ikm);
	const ecdh = createECDH(kem.curve);
	ecdh.setPrivateKey(sender.secret);
	const dh = new Uint8Array(ecdh.computeSecret(pkR));
	const { key, nonce } = scheduled(dh, sender.point, pkR, info);
	const cipher = createCipheriv(aead.cipher, key, nonce).setAAD(aad);
	const ct = joined(cipher.update(plaintext), cipher.final(), cipher.getAuthTag());
	return { enc: sender.point, ct };
}

/**
 * Opens one sealing to the recipient whose point is `pkR`, its Diffie-Hellman with the sender's
 * point (checked on the curve first) given by `agree`; none where it does not open (another key,
 * info, additional data, or bytes changed). What `agree` answers other than a shared secret is
 * passed on as it is.
 */
export async function openWith<W>(
	agree: (pkE: Uint8Array) => Promise<Uint8Array | W>,
	pkR: Uint8Array,
	sealed: Sealing,
	info: Uint8Array,
	aad: Uint8Array,
): Promise<Uint8Array | W | undefined> {
	if (!onCurve(sealed.enc) || sealed.ct.length < aead.tag) return undefined;
	const dh = await agree(sealed.enc);
	if (!(dh instanceof Uint8Array)) return dh;
	const { key, nonce } = scheduled(dh, sealed.enc, pkR, info);
	const body = sealed.ct.subarray(0, sealed.ct.length - aead.tag);
	try {
		const decipher = createDecipheriv(aead.cipher, key, nonce).setAAD(aad);
		decipher.setAuthTag(sealed.ct.subarray(sealed.ct.length - aead.tag));
		return joined(decipher.update(body), decipher.final());
	} catch {
		return undefined;
	}
}
