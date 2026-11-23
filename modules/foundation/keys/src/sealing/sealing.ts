import { createPublicKey } from "node:crypto";
import type { Log, Random } from "@mod/kernel";
import { hpke } from "@mod/sdk-core-wire";
import { sealing as preimages } from "@mod/transparency-wire";
import type { KeyHolder, Keys } from "../contract.ts";
import type { SealingKey } from "../rings/ring.ts";
import { openWith, sealTo } from "./hpke.ts";

const encoder = new TextEncoder();
/** What the Core opens: what a screen sealed to it, under sdk-core-wire's info. */
const opened: readonly string[] = Object.values(hpke.info);
/**
 * What the Core seals: to a screen, and a preimage to a monitor's key under transparency-wire's
 * info, where its suite is the one implemented here. The Core opens no preimage: it holds no
 * monitor's key.
 */
const sealed: readonly string[] = [
	...opened,
	...(preimages.kem === hpke.kem && preimages.kdf === hpke.kdf && preimages.aead === hpke.aead
		? [preimages.info]
		: []),
];

/** The info's bytes, where it is one of `allowed`; else the caller's TypeError. */
function infoOf(info: string, allowed: readonly string[]): Uint8Array {
	if (!allowed.includes(info)) throw new TypeError("keys: an HPKE info not sealed or opened here");
	return encoder.encode(info);
}

/** A peer's point as the platform reads a public key. */
const peerOf = (point: Uint8Array) =>
	createPublicKey({
		key: {
			kty: "EC",
			crv: "P-256",
			x: Buffer.from(point.subarray(1, 33)).toString("base64url"),
			y: Buffer.from(point.subarray(33)).toString("base64url"),
		},
		format: "jwk",
	});

/** Sealing to a screen's key in process, under a sender key drawn from the kernel's randomness; opening through the holder. */
export function sealing(
	holder: KeyHolder,
	key: SealingKey,
	random: Random,
	log: Log,
): Pick<Keys, "seal" | "open"> {
	return {
		seal: async (to, info, aad, plaintext) =>
			sealTo(to, infoOf(info, sealed), aad, plaintext, random.bytes(32)),
		open: async (box, info, aad) => {
			const agree = async (pkE: Uint8Array) => {
				const answer = await holder.agree(key.kid, peerOf(pkE));
				if (answer.kind === "agreed") return answer.shared;
				log.warn("keys.withdrawn", { use: "sealing", kid: key.kid });
				return "withdrawn" as const;
			};
			const plain = await openWith(agree, key.point, box, infoOf(info, opened), aad);
			if (plain === undefined) return { kind: "unopened" };
			if (plain === "withdrawn") return { kind: "withdrawn" };
			return { kind: "opened", plaintext: plain };
		},
	};
}
