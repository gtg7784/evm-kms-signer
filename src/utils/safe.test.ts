import type { Hex } from 'viem';
import { describe, expect, test } from 'vitest';
import { KmsSignerError } from '../errors/index.js';
import type { CoSignature } from '../types/index.js';
import { packSafeSignatures, sortSignaturesByAddress } from './safe.js';

const signatureOf = (byte: string): Hex => `0x${byte.repeat(65)}`;

const HIGH: CoSignature = {
	address: '0xfFfFfFfFfFfFfFfFfFfFfFfFfFfFfFfFfFfFfFfF',
	signature: signatureOf('cc'),
};
const LOW: CoSignature = {
	address: '0x0000000000000000000000000000000000000001',
	signature: signatureOf('aa'),
};
const MID: CoSignature = {
	address: '0x8000000000000000000000000000000000000000',
	signature: signatureOf('bb'),
};

describe('sortSignaturesByAddress', () => {
	test('should sort signatures by address in ascending order', () => {
		// #given
		const signatures = [HIGH, LOW, MID];

		// #when
		const sorted = sortSignaturesByAddress(signatures);

		// #then
		expect(sorted).toEqual([LOW, MID, HIGH]);
		expect(signatures).toEqual([HIGH, LOW, MID]);
	});

	test('should throw when addresses are duplicated regardless of case', () => {
		// #given
		const duplicate: CoSignature = {
			address: HIGH.address.toLowerCase() as CoSignature['address'],
			signature: signatureOf('dd'),
		};

		// #when
		const sort = () => sortSignaturesByAddress([HIGH, LOW, duplicate]);

		// #then
		expect(sort).toThrow(KmsSignerError);
	});
});

describe('packSafeSignatures', () => {
	test('should concatenate signatures in ascending address order', () => {
		// #given
		const signatures = [MID, HIGH, LOW];

		// #when
		const packed = packSafeSignatures(signatures);

		// #then
		expect(packed).toBe(
			`0x${'aa'.repeat(65)}${'bb'.repeat(65)}${'cc'.repeat(65)}`,
		);
	});
});
