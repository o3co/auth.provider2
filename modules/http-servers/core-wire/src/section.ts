import { z } from "zod";

const file = (what: string) =>
	z.string().min(1).describe(`The path of a PEM file holding ${what}.`);

/** The operator section: the entrance's certificate, the Fronts' authority, the probe listener, and what a violation does. */
export const section = z.strictObject({
	"certificate-file": file("the Core entrance's certificate and its chain, read at boot"),
	"key-file": file("the certificate's private key, read at boot"),
	"front-authority-file": file("the authorities a Front instance's certificate must chain to"),
	"probe-host": z
		.string()
		.prefault("127.0.0.1")
		.describe("The address the probe listener listens on, serving the probe routes alone."),
	"probe-port": z
		.number()
		.int()
		.min(0)
		.max(65535)
		.prefault(8081)
		.describe("The probe listener's port; 0 takes a free one."),
	"on-violation": z
		.enum(["notify", "cut"])
		.prefault("notify")
		.describe(
			"What a frame no honest Front sends does beyond its warning: `notify`, nothing more; `cut`, the Front instance that sent it is refused until the Core restarts.",
		),
});

export type Section = z.output<typeof section>;
