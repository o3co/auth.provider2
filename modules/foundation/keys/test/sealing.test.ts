import { createECDH, generateKeyPairSync, type KeyObject } from "node:crypto";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { hpke } from "@mod/sdk-core-wire";
import { sealing as preimages } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import { keys } from "../src/contract.ts";
import keysModule from "../src/module.ts";
import { openWith, sealTo } from "../src/sealing/hpke.ts";
import { keysConfig, testHolder } from "../src/testing.ts";

const text = (value: string) => new TextEncoder().encode(value);
/** A P-256 key's point as HPKE writes it: uncompressed, 65 bytes. */
const pointOf = (key: KeyObject) => {
	const jwk = key.export({ format: "jwk" });
	return new Uint8Array(
		Buffer.concat([
			Buffer.of(4),
			Buffer.from(jwk.x as string, "base64url"),
			Buffer.from(jwk.y as string, "base64url"),
		]),
	);
};

async function booted() {
	const sealing = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const app = await assemble({
		modules: [keysModule, testHolder({ "seal-test": sealing.privateKey })],
		config: { ...kernelConfig(), ...keysConfig() },
		runtime: quietRuntime(),
	});
	return { k: app.get(keys), core: pointOf(sealing.publicKey) };
}

describe("sealing", () => {
	it("seals to the screen's key, for the screen alone to open, each time under a fresh key", async () => {
		const { k } = await booted();
		const screen = createECDH("prime256v1");
		screen.generateKeys();
		const to = new Uint8Array(screen.getPublicKey());
		const aad = text("t-hash");
		const sealed = await k.seal(to, hpke.info.completion, aad, text("completion"));
		const again = await k.seal(to, hpke.info.completion, aad, text("completion"));
		expect(Buffer.from(sealed.enc)).not.toEqual(Buffer.from(again.enc));
		const agree = async (pkE: Uint8Array) => new Uint8Array(screen.computeSecret(pkE));
		const opened = await openWith(agree, to, sealed, text(hpke.info.completion), aad);
		expect(opened && new TextDecoder().decode(opened)).toBe("completion");
	});

	it("opens what the screen sealed to the Core's sealing key, and nothing sealed otherwise", async () => {
		const { k, core } = await booted();
		const aad = text("first-key/start");
		const info = text(hpke.info.firstKeyRequest);
		const sealed = sealTo(
			core,
			info,
			aad,
			text('{"identifier":"a"}'),
			crypto.getRandomValues(new Uint8Array(32)),
		);
		const opened = await k.open(sealed, hpke.info.firstKeyRequest, aad);
		expect(opened.kind === "opened" && new TextDecoder().decode(opened.plaintext)).toBe(
			'{"identifier":"a"}',
		);
		expect(await k.open(sealed, hpke.info.firstKeyRequest, text("other"))).toEqual({
			kind: "unopened",
		});
		expect(await k.open(sealed, hpke.info.firstKeyCode, aad)).toEqual({ kind: "unopened" });
		expect(
			await k.open({ enc: sealed.enc.subarray(1), ct: sealed.ct }, hpke.info.firstKeyRequest, aad),
		).toEqual({
			kind: "unopened",
		});
	});

	it("seals and opens only under the info sdk-core-wire names, as the caller's TypeError", async () => {
		const { k, core } = await booted();
		await expect(k.seal(core, "another/v1", new Uint8Array(), text("x"))).rejects.toThrow(
			TypeError,
		);
		await expect(
			k.open({ enc: core, ct: new Uint8Array(16) }, "another/v1", new Uint8Array()),
		).rejects.toThrow(TypeError);
	});

	it("seals a preimage to a monitor's key under transparency-wire's info, and opens none under it, holding no monitor's key", async () => {
		const { k } = await booted();
		const monitor = createECDH("prime256v1");
		monitor.generateKeys();
		const to = new Uint8Array(monitor.getPublicKey());
		const aad = text(preimages.aad({ of: "subject", id: "s" }, "op", 1));
		const sealed = await k.seal(to, preimages.info, aad, text("preimage"));
		const agree = async (pkE: Uint8Array) => new Uint8Array(monitor.computeSecret(pkE));
		const opened = await openWith(agree, to, sealed, text(preimages.info), aad);
		expect(opened && new TextDecoder().decode(opened)).toBe("preimage");
		await expect(k.open(sealed, preimages.info, aad)).rejects.toThrow(TypeError);
	});
});
