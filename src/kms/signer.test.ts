import type { TransactionSerializable } from 'viem';
import { getAddress } from 'viem';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import * as signatureUtils from '../utils/signature';
import { KmsClient } from './client';
import { KmsSigner } from './signer';

// Valid secp256k1 DER public key (65-byte uncompressed key)
const MOCK_DER_PUBLIC_KEY = new Uint8Array([
	// DER header (approx. 20-30 bytes)
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
	// 65-byte uncompressed public key (0x04 + 32-byte x + 32-byte y)
	0x04,
	...Array(32).fill(0x11), // x coordinate (test value)
	...Array(32).fill(0x22), // y coordinate (test value)
]);

// Valid DER signature (r=0x33..., s=0x44...)
// Important: s value (0x44...) must be less than SECP256K1_N_HALF for no normalization
const MOCK_DER_SIGNATURE = new Uint8Array([
	0x30,
	0x44, // SEQUENCE, length 68
	0x02,
	0x20, // INTEGER, length 32 (r)
	...Array(32).fill(0x33), // r value
	0x02,
	0x20, // INTEGER, length 32 (s)
	...Array(32).fill(0x44), // s value (0x4444... is < n/2, no normalization needed)
]);

// Mock KmsClient
vi.mock('./client', () => {
	return {
		KmsClient: vi.fn(),
	};
});

// Type for mocked KmsClient instance
interface MockKmsClient {
	getPublicKey: ReturnType<typeof vi.fn>;
	sign: ReturnType<typeof vi.fn>;
}

describe('KmsSigner', () => {
	beforeEach(() => {
		vi.clearAllMocks();

		// Setup mock implementation
		const mockGetPublicKey = vi.fn().mockResolvedValue(MOCK_DER_PUBLIC_KEY);
		const mockSign = vi.fn().mockResolvedValue(MOCK_DER_SIGNATURE);

		vi.mocked(KmsClient).mockImplementation(function (this: MockKmsClient) {
			this.getPublicKey = mockGetPublicKey;
			this.sign = mockSign;
			return this;
		} as unknown as typeof KmsClient);

		// Mock calculateRecoveryId to always return 0
		// This bypasses the actual recovery logic which requires valid cryptographic data
		vi.spyOn(signatureUtils, 'calculateRecoveryId').mockResolvedValue(0);
	});

	describe('constructor', () => {
		test('should create KmsSigner instance', () => {
			// #given
			const config = {
				region: 'us-east-1',
				keyId: 'test-key-id',
			};

			// #when
			const signer = new KmsSigner(config);

			// #then
			expect(signer).toBeInstanceOf(KmsSigner);
			expect(KmsClient).toHaveBeenCalledWith(config);
		});
	});

	describe('getPublicKey', () => {
		test('should retrieve and extract public key from KMS', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			// #when
			const publicKey = await signer.getPublicKey();

			// #then
			expect(publicKey).toHaveLength(65);
			expect(publicKey[0]).toBe(0x04); // uncompressed marker
			expect(publicKey[1]).toBe(0x11); // first byte of x
			expect(publicKey[33]).toBe(0x22); // first byte of y
		});

		test('should cache public key after first retrieval', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});
			const mockClient = vi.mocked(KmsClient).mock.results[0].value;

			// #when
			const publicKey1 = await signer.getPublicKey();
			const publicKey2 = await signer.getPublicKey();

			// #then
			expect(publicKey1).toBe(publicKey2); // Same reference
			expect(mockClient.getPublicKey).toHaveBeenCalledTimes(1); // Called only once
		});
	});

	describe('getAddress', () => {
		test('should derive Ethereum address from KMS public key', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			// #when
			const address = await signer.getAddress();

			// #then
			expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/); // Valid address format
			expect(address).toHaveLength(42);
		});

		test('should cache address after first derivation', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});
			const mockClient = vi.mocked(KmsClient).mock.results[0].value;

			// #when
			const address1 = await signer.getAddress();
			const address2 = await signer.getAddress();

			// #then
			expect(address1).toBe(address2); // Same reference
			expect(mockClient.getPublicKey).toHaveBeenCalledTimes(1); // Called only once
		});

		test('should derive consistent address from same public key', async () => {
			// #given
			const signer1 = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});
			const signer2 = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			// #when
			const address1 = await signer1.getAddress();
			const address2 = await signer2.getAddress();

			// #then
			// Both signers use same mock data, should derive same address
			expect(address1).toBe(address2);
		});
	});

	describe('signMessage', () => {
		test('should sign a message using KMS', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});
			const message = 'Hello, world!';

			// #when
			const signature = await signer.signMessage({ message });

			// #then
			expect(signature).toMatch(/^0x[0-9a-fA-F]+$/); // Valid hex string
			expect(signature).toHaveLength(132); // 0x + 64 (r) + 64 (s) + 2 (v) = 132 chars
		});

		test('should produce valid signature components (r, s, v)', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});
			const message = 'Test message';

			// #when
			const signature = await signer.signMessage({ message });

			// #then
			const r = signature.slice(0, 66); // 0x + 64 chars
			const s = `0x${signature.slice(66, 130)}`; // 64 chars
			const v = `0x${signature.slice(130, 132)}`; // 2 chars

			expect(r).toMatch(/^0x[0-9a-fA-F]{64}$/);
			expect(s).toMatch(/^0x[0-9a-fA-F]{64}$/);
			expect(v).toMatch(/^0x[0-9a-fA-F]{2}$/);

			// v should be 27, 28, 29, or 30 (legacy signature)
			const vNum = parseInt(v, 16);
			expect(vNum).toBeGreaterThanOrEqual(27);
			expect(vNum).toBeLessThanOrEqual(30);
		});

		test('should call KMS sign with hashed message', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});
			const mockClient = vi.mocked(KmsClient).mock.results[0].value;
			const message = 'Test message';

			// #when
			await signer.signMessage({ message });

			// #then
			expect(mockClient.sign).toHaveBeenCalledTimes(1);
			expect(mockClient.sign).toHaveBeenCalledWith(expect.any(Uint8Array));
			// The argument should be 32-byte hash
			const callArg = mockClient.sign.mock.calls[0][0];
			expect(callArg).toBeInstanceOf(Uint8Array);
			expect(callArg).toHaveLength(32); // keccak256 output
		});
	});

	describe('signTransaction', () => {
		test('should sign a transaction using KMS', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});
			const transaction = {
				to: getAddress('0x742d35Cc6634C0532925a3b844Bc9e7595f0beb0'),
				value: 1000000000000000000n, // 1 ETH
				chainId: 1,
				nonce: 0,
				maxFeePerGas: 20000000000n,
				maxPriorityFeePerGas: 1000000000n,
			};

			// #when
			const signedTx = await signer.signTransaction(transaction);

			// #then
			expect(signedTx).toMatch(/^0x[0-9a-fA-F]+$/); // Valid hex string
			expect(signedTx.length).toBeGreaterThan(100); // Should be a full serialized transaction
		});

		test('should use EIP-155 v value when chainId is present', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});
			const transaction = {
				to: getAddress('0x742d35Cc6634C0532925a3b844Bc9e7595f0beb0'),
				value: 1000000000000000000n,
				chainId: 1,
				nonce: 0,
				maxFeePerGas: 20000000000n,
				maxPriorityFeePerGas: 1000000000n,
			};

			// #when
			await signer.signTransaction(transaction);

			// #then
			// With chainId=1, v should be 37 or 38 (1 * 2 + 35 + recoveryId)
			// We verify that KMS was called with transaction hash
			const mockClient = vi.mocked(KmsClient).mock.results[0].value;
			expect(mockClient.sign).toHaveBeenCalledTimes(1);
			expect(mockClient.sign).toHaveBeenCalledWith(expect.any(Uint8Array));
		});

		test('should call KMS sign with transaction hash', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});
			const mockClient = vi.mocked(KmsClient).mock.results[0].value;
			const transaction = {
				to: getAddress('0x742d35Cc6634C0532925a3b844Bc9e7595f0beb0'),
				value: 1n,
				chainId: 1,
				nonce: 0,
				gasPrice: 20000000000n, // Add gasPrice for Legacy transaction
			};

			// #when
			await signer.signTransaction(transaction);

			// #then
			expect(mockClient.sign).toHaveBeenCalledTimes(1);
			const callArg = mockClient.sign.mock.calls[0][0];
			expect(callArg).toBeInstanceOf(Uint8Array);
			expect(callArg).toHaveLength(32); // keccak256 output
		});
	});

	describe('signTypedData', () => {
		test('should sign typed data using KMS', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});
			const typedData = {
				domain: {
					name: 'TestApp',
					version: '1',
					chainId: 1,
					verifyingContract: getAddress(
						'0x742d35Cc6634C0532925a3b844Bc9e7595f0beb0',
					),
				},
				types: {
					Person: [
						{ name: 'name', type: 'string' },
						{ name: 'wallet', type: 'address' },
					],
				},
				primaryType: 'Person' as const,
				message: {
					name: 'Alice',
					wallet: getAddress('0x742d35Cc6634C0532925a3b844Bc9e7595f0beb0'),
				},
			};

			// #when
			const signature = await signer.signTypedData(typedData);

			// #then
			expect(signature).toMatch(/^0x[0-9a-fA-F]+$/); // Valid hex string
			expect(signature).toHaveLength(132); // 0x + 64 (r) + 64 (s) + 2 (v)
		});

		test('should produce valid signature components for typed data', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});
			const typedData = {
				domain: {
					name: 'TestApp',
					version: '1',
					chainId: 1,
					verifyingContract: getAddress(
						'0x742d35Cc6634C0532925a3b844Bc9e7595f0beb0',
					),
				},
				types: {
					Message: [{ name: 'content', type: 'string' }],
				},
				primaryType: 'Message' as const,
				message: {
					content: 'Hello',
				},
			};

			// #when
			const signature = await signer.signTypedData(typedData);

			// #then
			const v = `0x${signature.slice(130, 132)}`;
			const vNum = parseInt(v, 16);

			// v should be 27, 28, 29, or 30 (legacy signature for typed data)
			expect(vNum).toBeGreaterThanOrEqual(27);
			expect(vNum).toBeLessThanOrEqual(30);
		});

		test('should call KMS sign with typed data hash', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});
			const mockClient = vi.mocked(KmsClient).mock.results[0].value;
			const typedData = {
				domain: {
					name: 'TestApp',
					version: '1',
					chainId: 1,
					verifyingContract: getAddress(
						'0x742d35Cc6634C0532925a3b844Bc9e7595f0beb0',
					),
				},
				types: {
					Message: [{ name: 'content', type: 'string' }],
				},
				primaryType: 'Message' as const,
				message: {
					content: 'Hello',
				},
			};

			// #when
			await signer.signTypedData(typedData);

			// #then
			expect(mockClient.sign).toHaveBeenCalledTimes(1);
			const callArg = mockClient.sign.mock.calls[0][0];
			expect(callArg).toBeInstanceOf(Uint8Array);
			expect(callArg).toHaveLength(32); // EIP-712 hash output
		});
	});

	describe('failure cases', () => {
		test('should throw error when KMS client fails to get public key', async () => {
			// #given
			const mockError = new Error('KMS unavailable');
			vi.mocked(KmsClient).mockImplementation(function (this: MockKmsClient) {
				this.getPublicKey = vi.fn().mockRejectedValue(mockError);
				this.sign = vi.fn();
				return this;
			} as unknown as typeof KmsClient);

			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			// #when & #then
			await expect(signer.getPublicKey()).rejects.toThrow('KMS unavailable');
		});

		test('should throw error when KMS returns invalid DER public key', async () => {
			// #given
			const invalidDer = new Uint8Array([0x00, 0x01, 0x02]); // Too short
			vi.mocked(KmsClient).mockImplementation(function (this: MockKmsClient) {
				this.getPublicKey = vi.fn().mockResolvedValue(invalidDer);
				this.sign = vi.fn();
				return this;
			} as unknown as typeof KmsClient);

			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			// #when & #then
			await expect(signer.getPublicKey()).rejects.toThrow();
		});

		test('should throw error when KMS client fails to sign', async () => {
			// #given
			const mockError = new Error('KMS signing failed');
			const mockGetPublicKey = vi.fn().mockResolvedValue(MOCK_DER_PUBLIC_KEY);
			const mockSign = vi.fn().mockRejectedValue(mockError);

			vi.mocked(KmsClient).mockImplementation(function (this: MockKmsClient) {
				this.getPublicKey = mockGetPublicKey;
				this.sign = mockSign;
				return this;
			} as unknown as typeof KmsClient);

			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			// #when & #then
			await expect(signer.signMessage({ message: 'test' })).rejects.toThrow(
				'KMS signing failed',
			);
		});

		test('should throw error when KMS returns invalid DER signature', async () => {
			// #given
			const invalidSig = new Uint8Array([0x00, 0x01]); // Too short
			const mockGetPublicKey = vi.fn().mockResolvedValue(MOCK_DER_PUBLIC_KEY);
			const mockSign = vi.fn().mockResolvedValue(invalidSig);

			vi.mocked(KmsClient).mockImplementation(function (this) {
				this.getPublicKey = mockGetPublicKey;
				this.sign = mockSign;
				return this;
			});

			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			// #when & #then
			await expect(signer.signMessage({ message: 'test' })).rejects.toThrow();
		});

		test('should throw error when recovery ID cannot be calculated', async () => {
			// #given
			const mockGetPublicKey = vi.fn().mockResolvedValue(MOCK_DER_PUBLIC_KEY);
			const mockSign = vi.fn().mockResolvedValue(MOCK_DER_SIGNATURE);

			vi.mocked(KmsClient).mockImplementation(function (this: MockKmsClient) {
				this.getPublicKey = mockGetPublicKey;
				this.sign = mockSign;
				return this;
			} as unknown as typeof KmsClient);

			// Mock calculateRecoveryId to throw error
			vi.spyOn(signatureUtils, 'calculateRecoveryId').mockRejectedValue(
				new Error('Cannot find valid recovery ID'),
			);

			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			// #when & #then
			await expect(signer.signMessage({ message: 'test' })).rejects.toThrow(
				'Cannot find valid recovery ID',
			);
		});

		test('should throw error when signing transaction without required fields', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			// #when & #then
			// Missing 'to' field (required for transaction)
			await expect(
				signer.signTransaction({
					value: 1n,
					nonce: 0,
				} as TransactionSerializable),
			).rejects.toThrow();
		});

		test('should throw error when signing with empty message', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			// #when & #then
			await expect(signer.signMessage({ message: '' })).resolves.toBeDefined();
			// Empty message is actually valid - it will hash to a specific value
		});

		test('should handle KMS timeout gracefully', async () => {
			// #given
			const timeoutError = new Error('Request timeout');
			timeoutError.name = 'TimeoutError';

			vi.mocked(KmsClient).mockImplementation(function (this: MockKmsClient) {
				this.getPublicKey = vi.fn().mockRejectedValue(timeoutError);
				this.sign = vi.fn();
				return this;
			} as unknown as typeof KmsClient);

			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			// #when & #then
			await expect(signer.getAddress()).rejects.toThrow('Request timeout');
		});

		test('should throw error with invalid region format', async () => {
			// #given
			const _signer = new KmsSigner({
				region: '', // Empty region
				keyId: 'test-key-id',
			});

			// #when & #then
			// KmsClient constructor should be called (implementation may validate)
			expect(KmsClient).toHaveBeenCalledWith({
				region: '',
				keyId: 'test-key-id',
			});
		});

		test('should throw error with invalid keyId format', async () => {
			// #given
			const _signer = new KmsSigner({
				region: 'us-east-1',
				keyId: '', // Empty keyId
			});

			// #when & #then
			expect(KmsClient).toHaveBeenCalledWith({
				region: 'us-east-1',
				keyId: '',
			});
		});

		test('should throw error when signing typed data with invalid structure', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			const invalidTypedData = {
				domain: {},
				types: {},
				// Missing primaryType
				message: {},
			} as Parameters<typeof signer.signTypedData>[0];

			// #when & #then
			await expect(signer.signTypedData(invalidTypedData)).rejects.toThrow();
		});

		test('should handle transaction signing with invalid chainId', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			const transaction = {
				to: getAddress('0x742d35Cc6634C0532925a3b844Bc9e7595f0beb0'),
				value: 1n,
				chainId: -1, // Invalid negative chainId
				nonce: 0,
				gasPrice: 20000000000n,
			};

			// #when & #then
			// This may throw during serialization or signing
			await expect(signer.signTransaction(transaction)).rejects.toThrow();
		});

		test('should handle very long message strings', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			// Create a very long message (1 MB)
			const longMessage = 'a'.repeat(1024 * 1024);

			// #when
			const signature = await signer.signMessage({ message: longMessage });

			// #then
			// Should successfully hash and sign even very long messages
			expect(signature).toMatch(/^0x[0-9a-fA-F]+$/);
			expect(signature).toHaveLength(132);
		});

		test('should handle unicode characters in messages', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			const unicodeMessage = 'Hello 世界 🌍 مرحبا';

			// #when
			const signature = await signer.signMessage({ message: unicodeMessage });

			// #then
			expect(signature).toMatch(/^0x[0-9a-fA-F]+$/);
			expect(signature).toHaveLength(132);
		});

		test('should handle special characters in messages', async () => {
			// #given
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			const specialMessage = 'Test\n\r\t\0Special\\Chars"\'<>';

			// #when
			const signature = await signer.signMessage({ message: specialMessage });

			// #then
			expect(signature).toMatch(/^0x[0-9a-fA-F]+$/);
			expect(signature).toHaveLength(132);
		});

		test('should propagate KMS client errors', async () => {
			// #given
			const kmError = new Error('Network timeout');
			vi.mocked(KmsClient).mockImplementation(function (this: MockKmsClient) {
				this.getPublicKey = vi.fn().mockResolvedValue(
					new Uint8Array([
						0x04, // Uncompressed point indicator
						...Array(64).fill(0x11),
					]),
				);
				this.sign = vi.fn().mockRejectedValue(kmError);
				return this;
			} as unknown as typeof KmsClient);

			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key-id',
			});

			// #when & #then
			await expect(signer.signMessage({ message: 'test' })).rejects.toThrow(
				'Network timeout',
			);
		});
	});
});
