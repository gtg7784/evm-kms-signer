import type { LocalAccount } from 'viem';
import { toAccount } from 'viem/accounts';
import type { GcpSigner } from './gcp/signer';
import type { KmsSigner } from './kms/signer';

/**
 * Create a viem Account from KmsSigner.
 *
 * Wraps KmsSigner methods to match viem's Account interface,
 * enabling use with viem clients (walletClient, etc.)
 *
 * @param signer - KmsSigner instance
 * @returns viem Account with KMS signing capabilities
 *
 * @example
 * ```typescript
 * const signer = new KmsSigner({ region: 'us-east-1', keyId: 'key-id' })
 * const account = await toKmsAccount(signer)
 *
 * const client = createWalletClient({
 *   account,
 *   chain: mainnet,
 *   transport: http()
 * })
 * ```
 */
export async function toKmsAccount(signer: KmsSigner): Promise<LocalAccount> {
	const address = await signer.getAddress();

	return toAccount({
		address,
		signMessage: async ({ message }) => {
			// Convert SignableMessage to string for KmsSigner
			const messageStr =
				typeof message === 'string' ? message : message.raw.toString();
			return signer.signMessage({ message: messageStr });
		},
		signTransaction: async (transaction, options) =>
			signer.signTransaction(transaction, options),
		signTypedData: async (typedData) => signer.signTypedData(typedData),
	});
}

/**
 * Create a viem Account from GcpSigner.
 *
 * Wraps GcpSigner methods to match viem's Account interface,
 * enabling use with viem clients (walletClient, etc.)
 *
 * @param signer - GcpSigner instance
 * @returns viem Account with GCP KMS signing capabilities
 *
 * @example
 * ```typescript
 * const signer = new GcpSigner({
 *   projectId: 'my-project',
 *   locationId: 'global',
 *   keyRingId: 'my-keyring',
 *   keyId: 'my-key',
 *   keyVersion: '1'
 * })
 * const account = await toGcpKmsAccount(signer)
 *
 * const client = createWalletClient({
 *   account,
 *   chain: mainnet,
 *   transport: http()
 * })
 * ```
 */
export async function toGcpKmsAccount(
	signer: GcpSigner,
): Promise<LocalAccount> {
	const address = await signer.getAddress();

	return toAccount({
		address,
		signMessage: async ({ message }) => {
			// Convert SignableMessage to string for GcpSigner
			const messageStr =
				typeof message === 'string' ? message : message.raw.toString();
			return signer.signMessage({ message: messageStr });
		},
		signTransaction: async (transaction, options) =>
			signer.signTransaction(transaction, options),
		signTypedData: async (typedData) => signer.signTypedData(typedData),
	});
}
