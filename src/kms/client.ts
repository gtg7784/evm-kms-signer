import {
	GetPublicKeyCommand,
	KMSClient,
	MessageType,
	SignCommand,
	SigningAlgorithmSpec,
} from '@aws-sdk/client-kms';
import { KmsClientError } from '../errors/index.js';
import type { KmsConfig } from '../types/index.js';

/**
 * KmsClient wraps AWS KMS SDK operations for key management and signing.
 *
 * This class provides a simplified interface to AWS KMS for:
 * - Retrieving public keys from KMS
 * - Signing message digests with KMS-stored private keys
 *
 * @example
 * ```typescript
 * const client = new KmsClient({
 *   region: 'us-east-1',
 *   keyId: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
 * })
 *
 * const publicKey = await client.getPublicKey()
 * const signature = await client.sign(messageHash)
 * ```
 */
export class KmsClient {
	private client: KMSClient;
	private keyId: string;

	/**
	 * Creates a new KMS client instance.
	 *
	 * @param config - KMS configuration including region, keyId, and optional credentials
	 *
	 * @remarks
	 * If credentials are not provided, the AWS SDK will use the default credential provider chain:
	 * - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
	 * - EKS Pod Identity (AWS_CONTAINER_CREDENTIALS_FULL_URI)
	 * - ECS container credentials
	 * - EC2 instance metadata (IMDS)
	 * - Shared credentials file (~/.aws/credentials)
	 *
	 * For EKS deployments, simply omit the credentials parameter and configure
	 * Pod Identity association - the SDK will automatically discover credentials.
	 */
	constructor(config: KmsConfig) {
		this.client = new KMSClient({
			region: config.region,
			...(config.credentials && { credentials: config.credentials }),
		});
		this.keyId = config.keyId;
	}

	/**
	 * Retrieves the public key from AWS KMS.
	 *
	 * @returns The public key in DER-encoded SubjectPublicKeyInfo (SPKI) format
	 * @throws {KmsClientError} If the KMS API call fails or returns no public key
	 *
	 * @remarks
	 * The returned public key is in SPKI format with a variable-length DER header.
	 * The last 65 bytes contain the uncompressed secp256k1 public key (0x04 + x + y).
	 */
	async getPublicKey(): Promise<Uint8Array> {
		try {
			const command = new GetPublicKeyCommand({ KeyId: this.keyId });
			const response = await this.client.send(command);

			if (!response.PublicKey) {
				throw new KmsClientError('No public key returned from KMS');
			}

			return new Uint8Array(response.PublicKey);
		} catch (error) {
			if (error instanceof KmsClientError) throw error;
			throw new KmsClientError(
				`Failed to get public key from KMS: ${error instanceof Error ? error.message : 'Unknown error'}`,
				error instanceof Error ? error : undefined,
			);
		}
	}

	/**
	 * Signs a message hash using the KMS-stored private key.
	 *
	 * @param messageHash - The pre-hashed message to sign (32 bytes for keccak256)
	 * @returns The signature in DER-encoded format (SEQUENCE { INTEGER r, INTEGER s })
	 * @throws {KmsClientError} If the KMS API call fails or returns no signature
	 *
	 * @remarks
	 * - Uses MessageType.DIGEST because the message is already hashed
	 * - Uses ECDSA_SHA_256 signing algorithm (required for secp256k1)
	 * - The returned signature is DER-encoded and needs to be parsed to extract r and s values
	 */
	async sign(messageHash: Uint8Array): Promise<Uint8Array> {
		try {
			const command = new SignCommand({
				KeyId: this.keyId,
				Message: messageHash,
				MessageType: MessageType.DIGEST,
				SigningAlgorithm: SigningAlgorithmSpec.ECDSA_SHA_256,
			});
			const response = await this.client.send(command);

			if (!response.Signature) {
				throw new KmsClientError('No signature returned from KMS');
			}

			return new Uint8Array(response.Signature);
		} catch (error) {
			if (error instanceof KmsClientError) throw error;
			throw new KmsClientError(
				`Failed to sign with KMS: ${error instanceof Error ? error.message : 'Unknown error'}`,
				error instanceof Error ? error : undefined,
			);
		}
	}
}
