import { KeyManagementServiceClient } from '@google-cloud/kms';
import { KmsClientError } from '../errors/index.js';
import type { GcpKmsConfig } from '../types/index.js';

/**
 * GcpClient wraps GCP KMS SDK operations for key management and signing.
 *
 * This class provides a simplified interface to GCP KMS for:
 * - Retrieving public keys from KMS
 * - Signing message digests with KMS-stored private keys
 *
 * @example
 * ```typescript
 * const client = new GcpClient({
 *   projectId: 'my-project',
 *   locationId: 'global',
 *   keyRingId: 'my-keyring',
 *   keyId: 'my-key',
 *   keyVersion: '1'
 * })
 *
 * const publicKey = await client.getPublicKey()
 * const signature = await client.sign(messageHash)
 * ```
 */
export class GcpClient {
	private client: KeyManagementServiceClient;
	private keyName: string;

	/**
	 * Creates a new GCP KMS client instance.
	 *
	 * @param config - GCP KMS configuration including project, location, key ring, key, and version
	 *
	 * @remarks
	 * If keyFilename is not provided, the GCP SDK will use the default credential provider chain:
	 * - GOOGLE_APPLICATION_CREDENTIALS environment variable
	 * - Application Default Credentials (ADC)
	 * - Service account attached to the compute resource
	 */
	constructor(config: GcpKmsConfig) {
		this.client = new KeyManagementServiceClient(
			config.keyFilename ? { keyFilename: config.keyFilename } : {},
		);

		// Construct the full key resource name
		// Format: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}/cryptoKeyVersions/{version}
		this.keyName = `projects/${config.projectId}/locations/${config.locationId}/keyRings/${config.keyRingId}/cryptoKeys/${config.keyId}/cryptoKeyVersions/${config.keyVersion}`;
	}

	/**
	 * Retrieves the public key from GCP KMS.
	 *
	 * @returns The public key in DER-encoded SubjectPublicKeyInfo (SPKI) format
	 * @throws {KmsClientError} If the KMS API call fails or returns no public key
	 *
	 * @remarks
	 * GCP KMS returns the public key in PEM format, which is converted to DER format.
	 * The returned public key is in SPKI format with a variable-length DER header.
	 * The last 65 bytes contain the uncompressed secp256k1 public key (0x04 + x + y).
	 */
	async getPublicKey(): Promise<Uint8Array> {
		try {
			const [publicKey] = await this.client.getPublicKey({
				name: this.keyName,
			});

			if (!publicKey.pem) {
				throw new KmsClientError('No public key returned from GCP KMS');
			}

			// Convert PEM to DER format
			return this.pemToDer(publicKey.pem);
		} catch (error) {
			if (error instanceof KmsClientError) throw error;
			throw new KmsClientError(
				`Failed to get public key from GCP KMS: ${error instanceof Error ? error.message : 'Unknown error'}`,
				error instanceof Error ? error : undefined,
			);
		}
	}

	/**
	 * Signs a message hash using the GCP KMS-stored private key.
	 *
	 * @param messageHash - The pre-hashed message to sign (32 bytes for keccak256)
	 * @returns The signature in DER-encoded format (SEQUENCE { INTEGER r, INTEGER s })
	 * @throws {KmsClientError} If the KMS API call fails or returns no signature
	 *
	 * @remarks
	 * - The messageHash should already be hashed (e.g., with keccak256)
	 * - GCP KMS uses EC_SIGN_SECP256K1_SHA256 algorithm for signing
	 * - The returned signature is DER-encoded and needs to be parsed to extract r and s values
	 */
	async sign(messageHash: Uint8Array): Promise<Uint8Array> {
		try {
			// Create CRC32C checksum for message integrity
			const crc32c = this.calculateCrc32c(messageHash);

			const [response] = await this.client.asymmetricSign({
				name: this.keyName,
				digest: {
					sha256: messageHash,
				},
				digestCrc32c: {
					value: crc32c,
				},
			});

			if (!response.signature) {
				throw new KmsClientError('No signature returned from GCP KMS');
			}

			// Convert signature to Uint8Array
			const signatureBytes =
				typeof response.signature === 'string'
					? Buffer.from(response.signature, 'base64')
					: response.signature instanceof Buffer
						? response.signature
						: new Uint8Array(response.signature);

			// Verify the signature CRC32C if provided
			if (response.signatureCrc32c && response.verifiedDigestCrc32c) {
				const signatureCrc32c = this.calculateCrc32c(
					signatureBytes instanceof Buffer
						? new Uint8Array(signatureBytes)
						: signatureBytes,
				);
				if (signatureCrc32c !== Number(response.signatureCrc32c.value)) {
					throw new KmsClientError(
						'Signature CRC32C verification failed - data may be corrupted',
					);
				}
			}

			return signatureBytes instanceof Buffer
				? new Uint8Array(signatureBytes)
				: signatureBytes;
		} catch (error) {
			if (error instanceof KmsClientError) throw error;
			throw new KmsClientError(
				`Failed to sign with GCP KMS: ${error instanceof Error ? error.message : 'Unknown error'}`,
				error instanceof Error ? error : undefined,
			);
		}
	}

	/**
	 * Converts PEM-encoded data to DER-encoded format.
	 *
	 * @param pem - PEM-encoded public key string
	 * @returns DER-encoded public key as Uint8Array
	 * @throws {KmsClientError} If PEM format is invalid
	 *
	 * @remarks
	 * PEM format consists of:
	 * - Header line: -----BEGIN PUBLIC KEY-----
	 * - Base64-encoded DER data
	 * - Footer line: -----END PUBLIC KEY-----
	 *
	 * This method extracts the Base64 data and decodes it to DER format.
	 */
	private pemToDer(pem: string): Uint8Array {
		try {
			// Remove PEM header, footer, and whitespace
			const base64 = pem
				.replace(/-----BEGIN PUBLIC KEY-----/, '')
				.replace(/-----END PUBLIC KEY-----/, '')
				.replace(/\s/g, '');

			// Decode Base64 to DER
			return Uint8Array.from(Buffer.from(base64, 'base64'));
		} catch (error) {
			throw new KmsClientError(
				`Failed to convert PEM to DER: ${error instanceof Error ? error.message : 'Unknown error'}`,
				error instanceof Error ? error : undefined,
			);
		}
	}

	/**
	 * Calculates CRC32C checksum for data integrity verification.
	 *
	 * @param data - Data to calculate checksum for
	 * @returns CRC32C checksum as number
	 *
	 * @remarks
	 * GCP KMS requires CRC32C checksums for request/response integrity verification.
	 * This is a simple implementation using a lookup table.
	 */
	private calculateCrc32c(data: Uint8Array): number {
		// CRC32C polynomial lookup table
		const crc32cTable = new Int32Array(256);
		for (let i = 0; i < 256; i++) {
			let c = i;
			for (let j = 0; j < 8; j++) {
				c = c & 1 ? 0x82f63b78 ^ (c >>> 1) : c >>> 1;
			}
			crc32cTable[i] = c;
		}

		let crc = 0xffffffff;
		for (let i = 0; i < data.length; i++) {
			crc = crc32cTable[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);
		}

		return (crc ^ 0xffffffff) >>> 0;
	}
}
