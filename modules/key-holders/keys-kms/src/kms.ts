import {
	DeriveSharedSecretCommand,
	type DeriveSharedSecretCommandInput,
	type DeriveSharedSecretCommandOutput,
	GetPublicKeyCommand,
	type GetPublicKeyCommandInput,
	type GetPublicKeyCommandOutput,
	KMSClient,
	SignCommand,
	type SignCommandInput,
	type SignCommandOutput,
} from "@aws-sdk/client-kms";

/** The calls of KMS this adapter makes, and the end of its client. */
export interface Kms {
	getPublicKey(input: GetPublicKeyCommandInput): Promise<GetPublicKeyCommandOutput>;
	sign(input: SignCommandInput): Promise<SignCommandOutput>;
	deriveSharedSecret(
		input: DeriveSharedSecretCommandInput,
	): Promise<DeriveSharedSecretCommandOutput>;
	destroy(): void;
}

/** KMS in the region given, through the SDK's client, its credentials the Core's own (the SDK's default chain). */
export function kmsIn(region: string): Kms {
	const client = new KMSClient({ region });
	return {
		getPublicKey: (input) => client.send(new GetPublicKeyCommand(input)),
		sign: (input) => client.send(new SignCommand(input)),
		deriveSharedSecret: (input) => client.send(new DeriveSharedSecretCommand(input)),
		destroy: () => client.destroy(),
	};
}
