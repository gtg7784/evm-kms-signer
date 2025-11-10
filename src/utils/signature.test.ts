import type { Address, Hex } from 'viem';
import { describe, expect, test } from 'vitest';
import {
	RecoveryIdCalculationError,
	SignatureNormalizationError,
} from '../errors';
import {
	calculateRecoveryId,
	calculateV,
	normalizeS,
	SECP256K1_N,
	SECP256K1_N_HALF,
	uint8ArrayToBigInt,
} from './signature';

describe('normalizeS', () => {
	test('should normalize s when s > n/2', () => {
		// #given
		// s value in upper half of curve order
		const s = SECP256K1_N_HALF + 1n;

		// #when
		const normalized = normalizeS(s);

		// #then
		expect(normalized).toBeLessThanOrEqual(SECP256K1_N_HALF);
		expect(normalized).toBe(SECP256K1_N - s);
	});

	test('should keep s unchanged when s <= n/2', () => {
		// #given
		// s value in lower half of curve order
		const s = SECP256K1_N_HALF - 1n;

		// #when
		const normalized = normalizeS(s);

		// #then
		expect(normalized).toBe(s);
	});

	test('should keep s unchanged when s = n/2', () => {
		// #given
		const s = SECP256K1_N_HALF;

		// #when
		const normalized = normalizeS(s);

		// #then
		expect(normalized).toBe(s);
	});

	test('should throw SignatureNormalizationError when s <= 0', () => {
		// #given
		const s = 0n;

		// #when & #then
		expect(() => normalizeS(s)).toThrow(SignatureNormalizationError);
		expect(() => normalizeS(s)).toThrow('s value out of valid range');
	});

	test('should throw SignatureNormalizationError when s >= n', () => {
		// #given
		const s = SECP256K1_N;

		// #when & #then
		expect(() => normalizeS(s)).toThrow(SignatureNormalizationError);
		expect(() => normalizeS(s)).toThrow('s value out of valid range');
	});

	test('should throw SignatureNormalizationError when s is negative', () => {
		// #given
		const s = -1n;

		// #when & #then
		expect(() => normalizeS(s)).toThrow(SignatureNormalizationError);
	});
});

describe('calculateV', () => {
	test('should calculate legacy v value (27) for recoveryId 0', () => {
		// #given
		const recoveryId = 0;

		// #when
		const v = calculateV(recoveryId);

		// #then
		expect(v).toBe(27n);
	});

	test('should calculate legacy v value (28) for recoveryId 1', () => {
		// #given
		const recoveryId = 1;

		// #when
		const v = calculateV(recoveryId);

		// #then
		expect(v).toBe(28n);
	});

	test('should calculate EIP-155 v value for chainId 1 and recoveryId 0', () => {
		// #given
		const recoveryId = 0;
		const chainId = 1;

		// #when
		const v = calculateV(recoveryId, chainId);

		// #then
		// v = chainId * 2 + 35 + recoveryId = 1 * 2 + 35 + 0 = 37
		expect(v).toBe(37n);
	});

	test('should calculate EIP-155 v value for chainId 1 and recoveryId 1', () => {
		// #given
		const recoveryId = 1;
		const chainId = 1;

		// #when
		const v = calculateV(recoveryId, chainId);

		// #then
		// v = chainId * 2 + 35 + recoveryId = 1 * 2 + 35 + 1 = 38
		expect(v).toBe(38n);
	});

	test('should calculate EIP-155 v value for chainId 137 (Polygon)', () => {
		// #given
		const recoveryId = 0;
		const chainId = 137;

		// #when
		const v = calculateV(recoveryId, chainId);

		// #then
		// v = chainId * 2 + 35 + recoveryId = 137 * 2 + 35 + 0 = 309
		expect(v).toBe(309n);
	});

	test('should throw RecoveryIdCalculationError when recoveryId < 0', () => {
		// #given
		const recoveryId = -1;

		// #when & #then
		expect(() => calculateV(recoveryId)).toThrow(RecoveryIdCalculationError);
		expect(() => calculateV(recoveryId)).toThrow('Invalid recovery ID');
	});

	test('should throw RecoveryIdCalculationError when recoveryId > 3', () => {
		// #given
		const recoveryId = 4;

		// #when & #then
		expect(() => calculateV(recoveryId)).toThrow(RecoveryIdCalculationError);
		expect(() => calculateV(recoveryId)).toThrow('Invalid recovery ID');
	});
});

describe('uint8ArrayToBigInt', () => {
	test('should convert Uint8Array to bigint', () => {
		// #given
		const bytes = new Uint8Array([0x01, 0x02, 0x03, 0x04]);

		// #when
		const value = uint8ArrayToBigInt(bytes);

		// #then
		expect(value).toBe(0x01020304n);
	});

	test('should convert single byte Uint8Array to bigint', () => {
		// #given
		const bytes = new Uint8Array([0xff]);

		// #when
		const value = uint8ArrayToBigInt(bytes);

		// #then
		expect(value).toBe(0xffn);
	});

	test('should return 0n for empty Uint8Array', () => {
		// #given
		const bytes = new Uint8Array([]);

		// #when
		const value = uint8ArrayToBigInt(bytes);

		// #then
		expect(value).toBe(0n);
	});

	test('should convert 32-byte Uint8Array (typical r/s value)', () => {
		// #given
		const bytes = new Uint8Array(32).fill(0x11);

		// #when
		const value = uint8ArrayToBigInt(bytes);

		// #then
		expect(value).toBe(
			0x1111111111111111111111111111111111111111111111111111111111111111n,
		);
	});

	test('should handle leading zeros correctly', () => {
		// #given
		const bytes = new Uint8Array([0x00, 0x00, 0x01, 0x02]);

		// #when
		const value = uint8ArrayToBigInt(bytes);

		// #then
		expect(value).toBe(0x0102n);
	});

	test('should handle all zeros correctly', () => {
		// #given
		const bytes = new Uint8Array([0x00, 0x00, 0x00, 0x00]);

		// #when
		const value = uint8ArrayToBigInt(bytes);

		// #then
		expect(value).toBe(0n);
	});

	test('should handle maximum 32-byte value (all 0xFF)', () => {
		// #given
		const bytes = new Uint8Array(32).fill(0xff);

		// #when
		const value = uint8ArrayToBigInt(bytes);

		// #then
		expect(value).toBe(
			0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
		);
	});

	test('should handle 64-byte array (larger than typical signature component)', () => {
		// #given
		const bytes = new Uint8Array(64).fill(0x11);

		// #when
		const value = uint8ArrayToBigInt(bytes);

		// #then
		// Should successfully convert even oversized arrays
		expect(value).toBeGreaterThan(0n);
	});
});

describe('normalizeS - additional failure cases', () => {
	test('should throw SignatureNormalizationError when s is exactly n', () => {
		// #given
		const s = SECP256K1_N;

		// #when & #then
		expect(() => normalizeS(s)).toThrow(SignatureNormalizationError);
		expect(() => normalizeS(s)).toThrow('s value out of valid range');
	});

	test('should throw SignatureNormalizationError when s > n', () => {
		// #given
		const s = SECP256K1_N + 1n;

		// #when & #then
		expect(() => normalizeS(s)).toThrow(SignatureNormalizationError);
		expect(() => normalizeS(s)).toThrow('s value out of valid range');
	});

	test('should throw SignatureNormalizationError when s is very large (2 * n)', () => {
		// #given
		const s = SECP256K1_N * 2n;

		// #when & #then
		expect(() => normalizeS(s)).toThrow(SignatureNormalizationError);
	});

	test('should handle s = 1 correctly', () => {
		// #given
		const s = 1n;

		// #when
		const normalized = normalizeS(s);

		// #then
		expect(normalized).toBe(1n);
	});

	test('should handle s = n - 1 correctly (just below n)', () => {
		// #given
		const s = SECP256K1_N - 1n;

		// #when
		const normalized = normalizeS(s);

		// #then
		// Should normalize to 1n (since n - (n - 1) = 1)
		expect(normalized).toBe(1n);
		expect(normalized).toBeLessThanOrEqual(SECP256K1_N_HALF);
	});
});

describe('calculateV - additional failure cases', () => {
	test('should throw RecoveryIdCalculationError when recoveryId is 5', () => {
		// #given
		const recoveryId = 5;

		// #when & #then
		expect(() => calculateV(recoveryId)).toThrow(RecoveryIdCalculationError);
		expect(() => calculateV(recoveryId)).toThrow('Invalid recovery ID');
	});

	test('should throw RecoveryIdCalculationError when recoveryId is -999', () => {
		// #given
		const recoveryId = -999;

		// #when & #then
		expect(() => calculateV(recoveryId)).toThrow(RecoveryIdCalculationError);
	});

	test('should throw error when recoveryId is fractional (via type coercion)', () => {
		// #given
		const recoveryId = 1.5 as number;

		// #when & #then
		// Will throw RangeError from BigInt conversion, not RecoveryIdCalculationError
		expect(() => calculateV(recoveryId)).toThrow();
		expect(() => calculateV(recoveryId)).toThrow(
			'cannot be converted to a BigInt',
		);
	});

	test('should handle chainId 0 correctly', () => {
		// #given
		const recoveryId = 0;
		const chainId = 0;

		// #when
		const v = calculateV(recoveryId, chainId);

		// #then
		// v = 0 * 2 + 35 + 0 = 35
		expect(v).toBe(35n);
	});

	test('should handle very large chainId (e.g. 999999999)', () => {
		// #given
		const recoveryId = 1;
		const chainId = 999999999;

		// #when
		const v = calculateV(recoveryId, chainId);

		// #then
		// v = 999999999 * 2 + 35 + 1 = 2000000034
		expect(v).toBe(2000000034n);
	});

	test('should handle recoveryId 2 with legacy signature', () => {
		// #given
		const recoveryId = 2;

		// #when
		const v = calculateV(recoveryId);

		// #then
		expect(v).toBe(29n);
	});

	test('should handle recoveryId 3 with legacy signature', () => {
		// #given
		const recoveryId = 3;

		// #when
		const v = calculateV(recoveryId);

		// #then
		expect(v).toBe(30n);
	});

	test('should handle recoveryId 3 with chainId 11155111 (Sepolia)', () => {
		// #given
		const recoveryId = 3;
		const chainId = 11155111;

		// #when
		const v = calculateV(recoveryId, chainId);

		// #then
		// v = 11155111 * 2 + 35 + 3 = 22310260
		expect(v).toBe(22310260n);
	});
});

describe('calculateRecoveryId', () => {
	test('should throw RecoveryIdCalculationError when no valid recovery ID found', async () => {
		// #given
		const messageHash =
			'0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef' as Hex;
		const r =
			'0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as Hex;
		const s =
			'0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' as Hex;
		const expectedAddress =
			'0x0000000000000000000000000000000000000000' as Address;

		// #when & #then
		await expect(
			calculateRecoveryId(messageHash, r, s, expectedAddress),
		).rejects.toThrow(RecoveryIdCalculationError);
		await expect(
			calculateRecoveryId(messageHash, r, s, expectedAddress),
		).rejects.toThrow('Cannot find valid recovery ID');
	});
});
