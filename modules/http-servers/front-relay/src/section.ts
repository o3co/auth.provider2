import { setting } from "@mod/kernel";
import { z } from "zod";

const file = (what: string) =>
	z.string().min(1).describe(`The path of a PEM file holding ${what}.`);

/** The operator section: where the Core's entrance is, the Front's certificate, and how long a reply may take. */
export const section = z.strictObject({
	"core-host": z.string().min(1).describe("The Core's entrance: its address or name."),
	"core-port": z.number().int().min(1).max(65535).describe("The port of the Core's entrance."),
	"server-name": z
		.string()
		.min(1)
		.optional()
		.describe("The name the Core's certificate is checked for; core-host when not set."),
	"certificate-file": file(
		"this Front instance's certificate and its chain, read at each connection",
	),
	"key-file": file("the certificate's private key, read at each connection"),
	"core-authority-file": file("the authorities the Core's certificate must chain to"),
	timeout: setting
		.duration("ms")
		.pipe(z.number().int().min(100).max(60_000))
		.prefault("10s")
		.describe("How long a request waits for the Core's reply, from 100ms to 1m, such as 10s."),
});

export type Section = z.output<typeof section>;
