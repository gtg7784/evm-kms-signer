import { beforeEach, describe, expect, test, vi } from 'vitest';
import { KmsClientError } from '../errors';
import type { GcpKmsConfig } from '../types';
import { GcpClient } from './client';

// Mock @google-cloud/kms SDK
vi.mock('@google-cloud/kms', () => ({
	KeyManagementServiceClient: vi.fn(),
}));

import { KeyManagementServiceClient } from '@google-cloud/kms';

// Mock config for testing
const mockConfig: GcpKmsConfig = {
	projectId: 'test-project',
	locationId: 'global',
	keyRingId: 'test-keyring',
	keyId: 'test-key',
	keyVersion: '1',
};

// Valid PEM-encoded public key
const MOCK_PEM_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEEREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg==
-----END PUBLIC KEY-----`;

// Expected DER output (base64-decoded content between BEGIN/END markers)
const EXPECTED_DER_PUBLIC_KEY = new Uint8Array([
	0x30,
	0x56,
	0x30,
	0x10,
	0x06,
	0x07,
	0x2a,
	0x86,
	0x48,
	0xce,
	0x3d,
	0x02,
	0x01,
	0x06,
	0x05,
	0x2b,
	0x81,
	0x04,
	0x00,
	0x0a,
	0x03,
	0x42,
	0x00,
	0x04,
	...Array(32).fill(0x11), // x coordinate
	...Array(32).fill(0x22), // y coordinate
]);

// Valid DER signature
const MOCK_DER_SIGNATURE = new Uint8Array([
	0x30,
	0x44, // SEQUENCE, length 68
	0x02,
	0x20, // INTEGER, length 32 (r)
	...Array(32).fill(0x33), // r value
	0x02,
	0x20, // INTEGER, length 32 (s)
	...Array(32).fill(0x44), // s value
]);

// Helper to create mock KMS client
const createMockKmsClient = (
	mockGetPublicKey: ReturnType<typeof vi.fn>,
	mockAsymmetricSign: ReturnType<typeof vi.fn>,
) => {
	vi.mocked(KeyManagementServiceClient).mockImplementation(function (this: {
		getPublicKey: typeof mockGetPublicKey;
		asymmetricSign: typeof mockAsymmetricSign;
	}) {
		this.getPublicKey = mockGetPublicKey;
		this.asymmetricSign = mockAsymmetricSign;
		return this;
	} as unknown as typeof KeyManagementServiceClient);
};

describe('GcpClient', () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	describe('constructor', () => {
		test('should create GcpClient instance with keyFilename', () => {
			// #given
			createMockKmsClient(vi.fn(), vi.fn());
			const configWithFile: GcpKmsConfig = {
				...mockConfig,
				keyFilename: '/path/to/key.json',
			};

			// #when
			const client = new GcpClient(configWithFile);

			// #then
			expect(client).toBeInstanceOf(GcpClient);
			expect(KeyManagementServiceClient).toHaveBeenCalledWith({
				keyFilename: '/path/to/key.json',
			});
		});

		test('should create GcpClient instance without keyFilename', () => {
			// #given
			createMockKmsClient(vi.fn(), vi.fn());

			// #when
			const client = new GcpClient(mockConfig);

			// #then
			expect(client).toBeInstanceOf(GcpClient);
			expect(KeyManagementServiceClient).toHaveBeenCalledWith({});
		});

		test('should construct correct key resource name', () => {
			// #given
			createMockKmsClient(vi.fn(), vi.fn());

			// #when
			const _client = new GcpClient(mockConfig);

			// #then
			// The keyName is constructed internally and used in API calls
			// We verify this indirectly through getPublicKey/sign calls
			expect(KeyManagementServiceClient).toHaveBeenCalled();
		});
	});

	describe('getPublicKey', () => {
		test('should return public key as Uint8Array when successful', async () => {
			// #given
			const mockGetPublicKey = vi.fn().mockResolvedValue([
				{
					pem: MOCK_PEM_PUBLIC_KEY,
				},
			]);
			createMockKmsClient(mockGetPublicKey, vi.fn());

			const client = new GcpClient(mockConfig);

			// #when
			const publicKey = await client.getPublicKey();

			// #then
			expect(publicKey).toBeInstanceOf(Uint8Array);
			expect(publicKey).toEqual(EXPECTED_DER_PUBLIC_KEY);
		});

		test('should call GCP KMS API with correct resource name', async () => {
			// #given
			const mockGetPublicKey = vi.fn().mockResolvedValue([
				{
					pem: MOCK_PEM_PUBLIC_KEY,
				},
			]);
			createMockKmsClient(mockGetPublicKey, vi.fn());

			const client = new GcpClient(mockConfig);

			// #when
			await client.getPublicKey();

			// #then
			expect(mockGetPublicKey).toHaveBeenCalledWith({
				name: 'projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key/cryptoKeyVersions/1',
			});
		});

		test('should throw KmsClientError when no PEM returned', async () => {
			// #given
			const mockGetPublicKey = vi.fn().mockResolvedValue([{}]); // No pem field
			createMockKmsClient(mockGetPublicKey, vi.fn());

			const client = new GcpClient(mockConfig);

			// #when & #then
			await expect(client.getPublicKey()).rejects.toThrow(KmsClientError);
			await expect(client.getPublicKey()).rejects.toThrow(
				'No public key returned from GCP KMS',
			);
		});

		test('should throw KmsClientError when API call fails', async () => {
			// #given
			const mockError = new Error('GCP API error');
			const mockGetPublicKey = vi.fn().mockRejectedValue(mockError);
			createMockKmsClient(mockGetPublicKey, vi.fn());

			const client = new GcpClient(mockConfig);

			// #when & #then
			await expect(client.getPublicKey()).rejects.toThrow(KmsClientError);
			await expect(client.getPublicKey()).rejects.toThrow(
				'Failed to get public key from GCP KMS',
			);
		});

		test('should handle PEM format correctly', async () => {
			// #given
			const mockGetPublicKey = vi.fn().mockResolvedValue([
				{
					pem: MOCK_PEM_PUBLIC_KEY,
				},
			]);
			createMockKmsClient(mockGetPublicKey, vi.fn());

			const client = new GcpClient(mockConfig);

			// #when
			const publicKey = await client.getPublicKey();

			// #then
			// Should successfully convert PEM to DER (returns full DER SPKI format)
			expect(publicKey).toBeInstanceOf(Uint8Array);
			expect(publicKey).toEqual(EXPECTED_DER_PUBLIC_KEY);
		});

		test('should rethrow KmsClientError without wrapping', async () => {
			// #given
			const originalError = new KmsClientError('Original error');
			const mockGetPublicKey = vi.fn().mockRejectedValue(originalError);
			createMockKmsClient(mockGetPublicKey, vi.fn());

			const client = new GcpClient(mockConfig);

			// #when & #then
			await expect(client.getPublicKey()).rejects.toThrow('Original error');
			await expect(client.getPublicKey()).rejects.toThrow(KmsClientError);
		});
	});

	describe('sign', () => {
		test('should return signature as Uint8Array when successful', async () => {
			// #given
			const mockAsymmetricSign = vi.fn().mockResolvedValue([
				{
					signature: MOCK_DER_SIGNATURE,
					// No CRC32C verification
				},
			]);
			createMockKmsClient(vi.fn(), mockAsymmetricSign);

			const client = new GcpClient(mockConfig);
			const messageHash = new Uint8Array(32).fill(0xaa);

			// #when
			const signature = await client.sign(messageHash);

			// #then
			expect(signature).toBeInstanceOf(Uint8Array);
			expect(signature).toEqual(MOCK_DER_SIGNATURE);
		});

		test('should call GCP KMS API with correct parameters', async () => {
			// #given
			const mockAsymmetricSign = vi.fn().mockResolvedValue([
				{
					signature: MOCK_DER_SIGNATURE,
					// No CRC32C verification
				},
			]);
			createMockKmsClient(vi.fn(), mockAsymmetricSign);

			const client = new GcpClient(mockConfig);
			const messageHash = new Uint8Array(32).fill(0xaa);

			// #when
			await client.sign(messageHash);

			// #then
			expect(mockAsymmetricSign).toHaveBeenCalledWith({
				name: 'projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key/cryptoKeyVersions/1',
				digest: {
					sha256: messageHash,
				},
				digestCrc32c: {
					value: expect.any(Number),
				},
			});
		});

		test('should throw KmsClientError when no signature returned', async () => {
			// #given
			const mockAsymmetricSign = vi.fn().mockResolvedValue([{}]); // No signature field
			createMockKmsClient(vi.fn(), mockAsymmetricSign);

			const client = new GcpClient(mockConfig);
			const messageHash = new Uint8Array(32).fill(0xaa);

			// #when & #then
			await expect(client.sign(messageHash)).rejects.toThrow(KmsClientError);
			await expect(client.sign(messageHash)).rejects.toThrow(
				'No signature returned from GCP KMS',
			);
		});

		test('should throw KmsClientError when API call fails', async () => {
			// #given
			const mockError = new Error('GCP signing error');
			const mockAsymmetricSign = vi.fn().mockRejectedValue(mockError);
			createMockKmsClient(vi.fn(), mockAsymmetricSign);

			const client = new GcpClient(mockConfig);
			const messageHash = new Uint8Array(32).fill(0xaa);

			// #when & #then
			await expect(client.sign(messageHash)).rejects.toThrow(KmsClientError);
			await expect(client.sign(messageHash)).rejects.toThrow(
				'Failed to sign with GCP KMS',
			);
		});

		test('should handle signature as string (base64)', async () => {
			// #given
			const base64Signature =
				Buffer.from(MOCK_DER_SIGNATURE).toString('base64');
			const mockAsymmetricSign = vi.fn().mockResolvedValue([
				{
					signature: base64Signature,
					// No CRC32C verification
				},
			]);
			createMockKmsClient(vi.fn(), mockAsymmetricSign);

			const client = new GcpClient(mockConfig);
			const messageHash = new Uint8Array(32).fill(0xaa);

			// #when
			const signature = await client.sign(messageHash);

			// #then
			expect(signature).toBeInstanceOf(Uint8Array);
		});

		test('should handle signature as Buffer', async () => {
			// #given
			const bufferSignature = Buffer.from(MOCK_DER_SIGNATURE);
			const mockAsymmetricSign = vi.fn().mockResolvedValue([
				{
					signature: bufferSignature,
					// No CRC32C verification
				},
			]);
			createMockKmsClient(vi.fn(), mockAsymmetricSign);

			const client = new GcpClient(mockConfig);
			const messageHash = new Uint8Array(32).fill(0xaa);

			// #when
			const signature = await client.sign(messageHash);

			// #then
			expect(signature).toBeInstanceOf(Uint8Array);
			expect(signature).toEqual(MOCK_DER_SIGNATURE);
		});

		test('should throw KmsClientError when CRC32C verification fails', async () => {
			// #given
			const mockAsymmetricSign = vi.fn().mockResolvedValue([
				{
					signature: MOCK_DER_SIGNATURE,
					signatureCrc32c: { value: 999999 }, // Wrong checksum
					verifiedDigestCrc32c: true,
				},
			]);
			createMockKmsClient(vi.fn(), mockAsymmetricSign);

			const client = new GcpClient(mockConfig);
			const messageHash = new Uint8Array(32).fill(0xaa);

			// #when & #then
			await expect(client.sign(messageHash)).rejects.toThrow(KmsClientError);
			await expect(client.sign(messageHash)).rejects.toThrow(
				'Signature CRC32C verification failed',
			);
		});

		test('should rethrow KmsClientError without wrapping', async () => {
			// #given
			const originalError = new KmsClientError('Original signing error');
			const mockAsymmetricSign = vi.fn().mockRejectedValue(originalError);
			createMockKmsClient(vi.fn(), mockAsymmetricSign);

			const client = new GcpClient(mockConfig);
			const messageHash = new Uint8Array(32).fill(0xaa);

			// #when & #then
			await expect(client.sign(messageHash)).rejects.toThrow(
				'Original signing error',
			);
			await expect(client.sign(messageHash)).rejects.toThrow(KmsClientError);
		});

		test('should skip CRC32C verification when not provided', async () => {
			// #given
			const mockAsymmetricSign = vi.fn().mockResolvedValue([
				{
					signature: MOCK_DER_SIGNATURE,
					// No CRC32C fields
				},
			]);
			createMockKmsClient(vi.fn(), mockAsymmetricSign);

			const client = new GcpClient(mockConfig);
			const messageHash = new Uint8Array(32).fill(0xaa);

			// #when
			const signature = await client.sign(messageHash);

			// #then
			expect(signature).toBeInstanceOf(Uint8Array);
			expect(signature).toEqual(MOCK_DER_SIGNATURE);
		});
	});

	describe('error handling', () => {
		test('should wrap non-Error objects in KmsClientError', async () => {
			// #given
			const mockGetPublicKey = vi.fn().mockRejectedValue('string error');
			createMockKmsClient(mockGetPublicKey, vi.fn());

			const client = new GcpClient(mockConfig);

			// #when & #then
			await expect(client.getPublicKey()).rejects.toThrow(KmsClientError);
			await expect(client.getPublicKey()).rejects.toThrow(
				'Failed to get public key from GCP KMS',
			);
		});

		test('should preserve original error as cause', async () => {
			// #given
			const originalError = new Error('Network timeout');
			const mockGetPublicKey = vi.fn().mockRejectedValue(originalError);
			createMockKmsClient(mockGetPublicKey, vi.fn());

			const client = new GcpClient(mockConfig);

			// #when
			try {
				await client.getPublicKey();
			} catch (error) {
				// #then
				expect(error).toBeInstanceOf(KmsClientError);
				if (error instanceof KmsClientError) {
					expect(error.cause).toBe(originalError);
				}
			}
		});
	});
});
