import { describe, expect, test } from 'vitest';
import { DerParsingError } from '../errors';
import { extractPublicKeyFromDer, publicKeyToAddress } from './address';

describe('extractPublicKeyFromDer', () => {
	test('should extract 65-byte public key from DER-encoded bytes', () => {
		// #given
		// Mock DER with header bytes + 65-byte uncompressed public key
		const mockDer = new Uint8Array([
			// DER header (variable length, simulating AWS KMS format)
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
			// 65-byte uncompressed public key (0x04 + x + y)
			0x04,
			...Array(32).fill(0x11), // x coordinate
			...Array(32).fill(0x22), // y coordinate
		]);

		// #when
		const publicKey = extractPublicKeyFromDer(mockDer);

		// #then
		expect(publicKey).toHaveLength(65);
		expect(publicKey[0]).toBe(0x04); // uncompressed marker
		expect(publicKey[1]).toBe(0x11); // first byte of x
		expect(publicKey[33]).toBe(0x22); // first byte of y
	});

	test('should validate that public key starts with 0x04', () => {
		// #given
		const mockDer = new Uint8Array([
			...Array(23).fill(0x00), // Header
			0x04, // Valid uncompressed marker
			...Array(64).fill(0x11),
		]);

		// #when
		const publicKey = extractPublicKeyFromDer(mockDer);

		// #then
		expect(publicKey[0]).toBe(0x04);
	});

	test('should throw DerParsingError when public key does not start with 0x04', () => {
		// #given
		// Compressed public key format (0x02 or 0x03)
		const mockDer = new Uint8Array([
			...Array(23).fill(0x00), // Header
			0x03, // Compressed marker (invalid)
			...Array(64).fill(0x11),
		]);

		// #when & #then
		expect(() => extractPublicKeyFromDer(mockDer)).toThrow(DerParsingError);
		expect(() => extractPublicKeyFromDer(mockDer)).toThrow(
			'Invalid public key format',
		);
		expect(() => extractPublicKeyFromDer(mockDer)).toThrow(
			'expected uncompressed',
		);
	});

	test('should handle exact 65-byte DER (edge case)', () => {
		// #given
		// DER that is exactly 65 bytes (no header)
		const mockDer = new Uint8Array([0x04, ...Array(64).fill(0xff)]);

		// #when
		const publicKey = extractPublicKeyFromDer(mockDer);

		// #then
		expect(publicKey).toHaveLength(65);
		expect(publicKey[0]).toBe(0x04);
	});
});

describe('publicKeyToAddress', () => {
	test('should derive Ethereum address from uncompressed public key', () => {
		// #given
		// Known test case: a predictable public key
		// Using a simple pattern for reproducibility
		const publicKey = new Uint8Array([
			0x04,
			// x coordinate (32 bytes of 0x11)
			...Array(32).fill(0x11),
			// y coordinate (32 bytes of 0x22)
			...Array(32).fill(0x22),
		]);

		// #when
		const address = publicKeyToAddress(publicKey);

		// #then
		expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/); // Valid Ethereum address format
		expect(address).toHaveLength(42); // 0x + 40 hex chars
		// The actual address value is deterministic from keccak256
		// We verify format rather than exact value
	});

	test('should produce consistent address for same public key', () => {
		// #given
		const publicKey = new Uint8Array([
			0x04,
			...Array(32).fill(0xaa),
			...Array(32).fill(0xbb),
		]);

		// #when
		const address1 = publicKeyToAddress(publicKey);
		const address2 = publicKeyToAddress(publicKey);

		// #then
		expect(address1).toBe(address2); // Deterministic
	});

	test('should produce different addresses for different public keys', () => {
		// #given
		const publicKey1 = new Uint8Array([
			0x04,
			...Array(32).fill(0x11),
			...Array(32).fill(0x22),
		]);
		const publicKey2 = new Uint8Array([
			0x04,
			...Array(32).fill(0x33),
			...Array(32).fill(0x44),
		]);

		// #when
		const address1 = publicKeyToAddress(publicKey1);
		const address2 = publicKeyToAddress(publicKey2);

		// #then
		expect(address1).not.toBe(address2);
	});

	test('should derive address using only x and y coordinates (excluding 0x04)', () => {
		// #given
		const publicKey = new Uint8Array([
			0x04,
			...Array(64).fill(0x01), // x + y coordinates
		]);

		// #when
		const address = publicKeyToAddress(publicKey);

		// #then
		// Address should be derived from keccak256 of 64 bytes (not 65)
		expect(address).toBeDefined();
		expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
		// The first byte (0x04) should not affect the hash
	});

	test('should handle public key with all zeros in coordinates', () => {
		// #given
		const publicKey = new Uint8Array([0x04, ...Array(64).fill(0x00)]);

		// #when
		const address = publicKeyToAddress(publicKey);

		// #then
		expect(address).toBeDefined();
		expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
	});

	test('should handle public key with all 0xff in coordinates', () => {
		// #given
		const publicKey = new Uint8Array([0x04, ...Array(64).fill(0xff)]);

		// #when
		const address = publicKeyToAddress(publicKey);

		// #then
		expect(address).toBeDefined();
		expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
	});
});

describe('extractPublicKeyFromDer - additional failure cases', () => {
	test('should throw DerParsingError when DER is too short (< 65 bytes)', () => {
		// #given
		const shortDer = new Uint8Array([
			...Array(30).fill(0x00), // Only 30 bytes total
			0x04,
			...Array(10).fill(0x11),
		]);

		// #when & #then
		expect(() => extractPublicKeyFromDer(shortDer)).toThrow(DerParsingError);
	});

	test('should throw DerParsingError when DER is exactly 64 bytes (missing uncompressed marker)', () => {
		// #given
		const der64Bytes = new Uint8Array(64).fill(0x11);

		// #when & #then
		expect(() => extractPublicKeyFromDer(der64Bytes)).toThrow(DerParsingError);
	});

	test('should throw DerParsingError when public key marker is 0x02 (compressed)', () => {
		// #given
		const compressedDer = new Uint8Array([
			...Array(23).fill(0x00),
			0x02, // Compressed marker
			...Array(64).fill(0x11),
		]);

		// #when & #then
		expect(() => extractPublicKeyFromDer(compressedDer)).toThrow(
			DerParsingError,
		);
		expect(() => extractPublicKeyFromDer(compressedDer)).toThrow(
			'expected uncompressed',
		);
	});

	test('should throw DerParsingError when public key marker is 0x00 (invalid)', () => {
		// #given
		const invalidDer = new Uint8Array([
			...Array(23).fill(0xff),
			0x00, // Invalid marker
			...Array(64).fill(0x11),
		]);

		// #when & #then
		expect(() => extractPublicKeyFromDer(invalidDer)).toThrow(DerParsingError);
	});

	test('should throw DerParsingError when DER is empty', () => {
		// #given
		const emptyDer = new Uint8Array([]);

		// #when & #then
		expect(() => extractPublicKeyFromDer(emptyDer)).toThrow(DerParsingError);
	});

	test('should handle minimum valid DER (exactly 65 bytes with 0x04)', () => {
		// #given
		const minimalDer = new Uint8Array([
			0x04,
			...Array(32).fill(0xaa), // x
			...Array(32).fill(0xbb), // y
		]);

		// #when
		const publicKey = extractPublicKeyFromDer(minimalDer);

		// #then
		expect(publicKey).toHaveLength(65);
		expect(publicKey[0]).toBe(0x04);
	});

	test('should handle very large DER (with extensive header)', () => {
		// #given
		const largeDer = new Uint8Array([
			...Array(200).fill(0x00), // Large header
			0x04,
			...Array(64).fill(0x11),
		]);

		// #when
		const publicKey = extractPublicKeyFromDer(largeDer);

		// #then
		expect(publicKey).toHaveLength(65);
		expect(publicKey[0]).toBe(0x04);
	});
});

describe('publicKeyToAddress - additional failure cases', () => {
	test('should throw error when public key is too short (< 65 bytes)', () => {
		// #given
		const shortPublicKey = new Uint8Array([
			0x04,
			...Array(32).fill(0x11), // Only x coordinate, missing y
		]);

		// #when & #then
		// publicKeyToAddress should fail when trying to slice 64 bytes from 33-byte array
		expect(() => publicKeyToAddress(shortPublicKey)).toThrow();
	});

	test('should throw error when public key is exactly 1 byte', () => {
		// #given
		const tinyPublicKey = new Uint8Array([0x04]);

		// #when & #then
		expect(() => publicKeyToAddress(tinyPublicKey)).toThrow();
	});

	test('should throw error when public key is empty', () => {
		// #given
		const emptyPublicKey = new Uint8Array([]);

		// #when & #then
		expect(() => publicKeyToAddress(emptyPublicKey)).toThrow();
	});

	test('should handle public key that is 66 bytes (1 extra byte)', () => {
		// #given
		const extraBytePublicKey = new Uint8Array([
			0x04,
			...Array(64).fill(0x11),
			0xff, // Extra byte (should be ignored by slice(1))
		]);

		// #when
		const address = publicKeyToAddress(extraBytePublicKey);

		// #then
		// Should successfully derive address (extra bytes ignored)
		expect(address).toBeDefined();
		expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
	});

	test('should handle public key with mixed byte values', () => {
		// #given
		const mixedPublicKey = new Uint8Array([
			0x04,
			...Array(16).fill(0x00),
			...Array(16).fill(0xff), // x coordinate mixed
			...Array(16).fill(0xaa),
			...Array(16).fill(0xbb), // y coordinate mixed
		]);

		// #when
		const address = publicKeyToAddress(mixedPublicKey);

		// #then
		expect(address).toBeDefined();
		expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
	});

	test('should produce lowercase address', () => {
		// #given
		const publicKey = new Uint8Array([0x04, ...Array(64).fill(0x11)]);

		// #when
		const address = publicKeyToAddress(publicKey);

		// #then
		// Addresses should be lowercase (viem convention)
		expect(address).toBe(address.toLowerCase());
	});

	test('should handle public key with alternating bytes', () => {
		// #given
		const alternatingBytes = [];
		for (let i = 0; i < 64; i++) {
			alternatingBytes.push(i % 2 === 0 ? 0x00 : 0xff);
		}
		const publicKey = new Uint8Array([0x04, ...alternatingBytes]);

		// #when
		const address = publicKeyToAddress(publicKey);

		// #then
		expect(address).toBeDefined();
		expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
	});
});
