import { describe, expect, test } from 'vitest';
import { DerParsingError } from '../errors';
import { parseDerSignature } from './der';

describe('parseDerSignature', () => {
	test('should parse valid DER signature with 32-byte r and s', () => {
		// #given
		// r = all 0x11, s = all 0x22
		const validDer = new Uint8Array([
			0x30,
			0x44, // SEQUENCE, length 68
			0x02,
			0x20, // INTEGER, length 32 (r)
			...Array(32).fill(0x11), // r value
			0x02,
			0x20, // INTEGER, length 32 (s)
			...Array(32).fill(0x22), // s value
		]);

		// #when
		const result = parseDerSignature(validDer);

		// #then
		expect(result.r).toHaveLength(32);
		expect(result.s).toHaveLength(32);
		expect(result.r[0]).toBe(0x11);
		expect(result.s[0]).toBe(0x22);
	});

	test('should remove leading 0x00 from 33-byte r value', () => {
		// #given
		// r is 33 bytes (0x00 + 32 bytes)
		const derWith33Bytes = new Uint8Array([
			0x30,
			0x45, // SEQUENCE, length 69
			0x02,
			0x21, // INTEGER, length 33 (r)
			0x00,
			...Array(32).fill(0x11), // leading 0x00 + r
			0x02,
			0x20, // INTEGER, length 32 (s)
			...Array(32).fill(0x22),
		]);

		// #when
		const result = parseDerSignature(derWith33Bytes);

		// #then
		expect(result.r).toHaveLength(32);
		expect(result.r[0]).toBe(0x11); // leading 0x00 removed
		expect(result.s).toHaveLength(32);
	});

	test('should remove leading 0x00 from 33-byte s value', () => {
		// #given
		// s is 33 bytes (0x00 + 32 bytes)
		const derWith33Bytes = new Uint8Array([
			0x30,
			0x45, // SEQUENCE, length 69
			0x02,
			0x20, // INTEGER, length 32 (r)
			...Array(32).fill(0x11),
			0x02,
			0x21, // INTEGER, length 33 (s)
			0x00,
			...Array(32).fill(0x22), // leading 0x00 + s
		]);

		// #when
		const result = parseDerSignature(derWith33Bytes);

		// #then
		expect(result.r).toHaveLength(32);
		expect(result.s).toHaveLength(32);
		expect(result.s[0]).toBe(0x22); // leading 0x00 removed
	});

	test('should pad r value to 32 bytes when less than 32 bytes', () => {
		// #given
		// r is 31 bytes (should be left-padded with zero)
		const derWithShortR = new Uint8Array([
			0x30,
			0x43, // SEQUENCE, length 67
			0x02,
			0x1f, // INTEGER, length 31 (r)
			...Array(31).fill(0x11), // r value (31 bytes)
			0x02,
			0x20, // INTEGER, length 32 (s)
			...Array(32).fill(0x22),
		]);

		// #when
		const result = parseDerSignature(derWithShortR);

		// #then
		expect(result.r).toHaveLength(32);
		expect(result.r[0]).toBe(0x00); // left-padded with zero
		expect(result.r[1]).toBe(0x11);
		expect(result.s).toHaveLength(32);
	});

	test('should pad s value to 32 bytes when less than 32 bytes', () => {
		// #given
		// s is 30 bytes (should be left-padded with zeros)
		const derWithShortS = new Uint8Array([
			0x30,
			0x42, // SEQUENCE, length 66
			0x02,
			0x20, // INTEGER, length 32 (r)
			...Array(32).fill(0x11),
			0x02,
			0x1e, // INTEGER, length 30 (s)
			...Array(30).fill(0x22), // s value (30 bytes)
		]);

		// #when
		const result = parseDerSignature(derWithShortS);

		// #then
		expect(result.r).toHaveLength(32);
		expect(result.s).toHaveLength(32);
		expect(result.s[0]).toBe(0x00); // left-padded with zero
		expect(result.s[1]).toBe(0x00);
		expect(result.s[2]).toBe(0x22);
	});

	test('should throw DerParsingError when SEQUENCE tag is missing', () => {
		// #given
		// Invalid DER starting with 0x31 instead of 0x30
		const invalidDer = new Uint8Array([
			0x31,
			0x44, // Invalid SEQUENCE tag
			0x02,
			0x20,
			...Array(32).fill(0x11),
			0x02,
			0x20,
			...Array(32).fill(0x22),
		]);

		// #when & #then
		expect(() => parseDerSignature(invalidDer)).toThrow(DerParsingError);
		expect(() => parseDerSignature(invalidDer)).toThrow(
			'expected SEQUENCE tag',
		);
	});

	test('should throw DerParsingError when r INTEGER tag is missing', () => {
		// #given
		// Invalid DER with wrong tag for r
		const invalidDer = new Uint8Array([
			0x30,
			0x44, // SEQUENCE
			0x03,
			0x20, // Wrong tag (0x03 instead of 0x02)
			...Array(32).fill(0x11),
			0x02,
			0x20,
			...Array(32).fill(0x22),
		]);

		// #when & #then
		expect(() => parseDerSignature(invalidDer)).toThrow(DerParsingError);
		expect(() => parseDerSignature(invalidDer)).toThrow('expected INTEGER tag');
		expect(() => parseDerSignature(invalidDer)).toThrow('for r');
	});

	test('should throw DerParsingError when s INTEGER tag is missing', () => {
		// #given
		// Invalid DER with wrong tag for s
		const invalidDer = new Uint8Array([
			0x30,
			0x44, // SEQUENCE
			0x02,
			0x20, // r INTEGER
			...Array(32).fill(0x11),
			0x03,
			0x20, // Wrong tag for s (0x03 instead of 0x02)
			...Array(32).fill(0x22),
		]);

		// #when & #then
		expect(() => parseDerSignature(invalidDer)).toThrow(DerParsingError);
		expect(() => parseDerSignature(invalidDer)).toThrow('expected INTEGER tag');
		expect(() => parseDerSignature(invalidDer)).toThrow('for s');
	});

	test('should throw DerParsingError when DER signature is empty', () => {
		// #given
		const emptyDer = new Uint8Array([]);

		// #when & #then
		expect(() => parseDerSignature(emptyDer)).toThrow(DerParsingError);
	});

	test('should throw DerParsingError when DER signature is too short', () => {
		// #given
		// Only SEQUENCE tag and length, missing data
		const shortDer = new Uint8Array([0x30, 0x44]);

		// #when & #then
		expect(() => parseDerSignature(shortDer)).toThrow(DerParsingError);
	});

	test('should throw DerParsingError when r length is invalid (0)', () => {
		// #given
		// r length is 0
		const invalidDer = new Uint8Array([
			0x30,
			0x24, // SEQUENCE
			0x02,
			0x00, // INTEGER with length 0 (invalid)
			0x02,
			0x20, // s INTEGER
			...Array(32).fill(0x22),
		]);

		// #when & #then
		expect(() => parseDerSignature(invalidDer)).toThrow(DerParsingError);
	});

	test('should throw DerParsingError when s length is invalid (0)', () => {
		// #given
		// s length is 0
		const invalidDer = new Uint8Array([
			0x30,
			0x24, // SEQUENCE
			0x02,
			0x20, // r INTEGER
			...Array(32).fill(0x11),
			0x02,
			0x00, // INTEGER with length 0 (invalid)
		]);

		// #when & #then
		expect(() => parseDerSignature(invalidDer)).toThrow(DerParsingError);
	});

	test('should throw DerParsingError when r value exceeds buffer length', () => {
		// #given
		// r length says 32 bytes but only 10 bytes available
		const invalidDer = new Uint8Array([
			0x30,
			0x44, // SEQUENCE
			0x02,
			0x20, // INTEGER, claims length 32
			...Array(10).fill(0x11), // but only 10 bytes provided
		]);

		// #when & #then
		expect(() => parseDerSignature(invalidDer)).toThrow(DerParsingError);
	});

	test('should throw DerParsingError when s value exceeds buffer length', () => {
		// #given
		// s length says 32 bytes but buffer ends early
		const invalidDer = new Uint8Array([
			0x30,
			0x44, // SEQUENCE
			0x02,
			0x20, // r INTEGER, length 32
			...Array(32).fill(0x11),
			0x02,
			0x20, // s INTEGER, claims length 32
			...Array(10).fill(0x22), // but only 10 bytes provided
		]);

		// #when & #then
		expect(() => parseDerSignature(invalidDer)).toThrow(DerParsingError);
	});

	test('should throw DerParsingError when r has excessive length (>33 bytes)', () => {
		// #given
		// r is 34 bytes (too long even with padding)
		const invalidDer = new Uint8Array([
			0x30,
			0x46, // SEQUENCE
			0x02,
			0x22, // INTEGER, length 34
			...Array(34).fill(0x11),
			0x02,
			0x20, // s INTEGER
			...Array(32).fill(0x22),
		]);

		// #when & #then
		expect(() => parseDerSignature(invalidDer)).toThrow(DerParsingError);
	});

	test('should throw DerParsingError when s has excessive length (>33 bytes)', () => {
		// #given
		// s is 35 bytes (too long)
		const invalidDer = new Uint8Array([
			0x30,
			0x47, // SEQUENCE
			0x02,
			0x20, // r INTEGER
			...Array(32).fill(0x11),
			0x02,
			0x23, // INTEGER, length 35
			...Array(35).fill(0x22),
		]);

		// #when & #then
		expect(() => parseDerSignature(invalidDer)).toThrow(DerParsingError);
	});

	test('should throw DerParsingError when SEQUENCE length is incorrect', () => {
		// #given
		// SEQUENCE length says 68 but actual data is shorter
		const invalidDer = new Uint8Array([
			0x30,
			0x44, // SEQUENCE claims length 68
			0x02,
			0x10, // r INTEGER, length 16 (actual)
			...Array(16).fill(0x11),
			0x02,
			0x10, // s INTEGER, length 16 (actual)
			...Array(16).fill(0x22),
		]);

		// #when & #then
		expect(() => parseDerSignature(invalidDer)).toThrow(DerParsingError);
	});

	test('should throw DerParsingError when both r and s have leading 0x00 padding', () => {
		// #given
		// Both r and s are 33 bytes with 0x00 padding
		const derWithBothPadded = new Uint8Array([
			0x30,
			0x46, // SEQUENCE, length 70
			0x02,
			0x21, // r INTEGER, length 33
			0x00,
			...Array(32).fill(0x11),
			0x02,
			0x21, // s INTEGER, length 33
			0x00,
			...Array(32).fill(0x22),
		]);

		// #when
		const result = parseDerSignature(derWithBothPadded);

		// #then
		// Should successfully remove both leading 0x00 bytes
		expect(result.r).toHaveLength(32);
		expect(result.s).toHaveLength(32);
		expect(result.r[0]).toBe(0x11);
		expect(result.s[0]).toBe(0x22);
	});

	test('should throw DerParsingError when buffer too short for r parsing', () => {
		// #given
		// SEQUENCE tag exists but buffer too short
		const invalidDer = new Uint8Array([
			0x30,
			0x10, // SEQUENCE
			// No INTEGER tag for r (buffer too short)
		]);

		// #when & #then
		expect(() => parseDerSignature(invalidDer)).toThrow(DerParsingError);
		expect(() => parseDerSignature(invalidDer)).toThrow('buffer too short');
	});

	test('should throw DerParsingError when buffer too short for r length', () => {
		// #given
		// Has INTEGER tag but missing length byte
		const invalidDer = new Uint8Array([
			0x30,
			0x10, // SEQUENCE
			0x02, // INTEGER tag but no length
		]);

		// #when & #then
		expect(() => parseDerSignature(invalidDer)).toThrow(DerParsingError);
		expect(() => parseDerSignature(invalidDer)).toThrow('buffer too short');
	});

	test('should throw DerParsingError when SEQUENCE length exceeds buffer (missing s)', () => {
		// #given
		// Has r but s INTEGER tag is missing - SEQUENCE length validation catches this
		const invalidDer = new Uint8Array([
			0x30,
			0x44, // SEQUENCE says 68 bytes
			0x02,
			0x20, // r INTEGER
			...Array(32).fill(0x11),
			// Missing s INTEGER tag - buffer only 36 bytes but SEQUENCE says 68
		]);

		// #when & #then
		expect(() => parseDerSignature(invalidDer)).toThrow(DerParsingError);
		expect(() => parseDerSignature(invalidDer)).toThrow(
			'SEQUENCE length exceeds buffer',
		);
	});
});
