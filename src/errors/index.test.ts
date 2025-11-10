import { describe, expect, test } from 'vitest';
import {
	DerParsingError,
	KmsClientError,
	KmsSignerError,
	RecoveryIdCalculationError,
	SignatureNormalizationError,
} from './index';

describe('KmsSignerError', () => {
	test('should create error with correct name and message', () => {
		// #given
		const message = 'Test error message';

		// #when
		const error = new KmsSignerError(message);

		// #then
		expect(error).toBeInstanceOf(Error);
		expect(error).toBeInstanceOf(KmsSignerError);
		expect(error.name).toBe('KmsSignerError');
		expect(error.message).toBe(message);
	});
});

describe('DerParsingError', () => {
	test('should create error with correct name and message', () => {
		// #given
		const message = 'Invalid DER format';

		// #when
		const error = new DerParsingError(message);

		// #then
		expect(error).toBeInstanceOf(Error);
		expect(error).toBeInstanceOf(KmsSignerError);
		expect(error).toBeInstanceOf(DerParsingError);
		expect(error.name).toBe('DerParsingError');
		expect(error.message).toBe(message);
	});
});

describe('KmsClientError', () => {
	test('should create error with correct name and message', () => {
		// #given
		const message = 'KMS API failed';

		// #when
		const error = new KmsClientError(message);

		// #then
		expect(error).toBeInstanceOf(Error);
		expect(error).toBeInstanceOf(KmsSignerError);
		expect(error).toBeInstanceOf(KmsClientError);
		expect(error.name).toBe('KmsClientError');
		expect(error.message).toBe(message);
		expect(error.cause).toBeUndefined();
	});

	test('should store cause when provided', () => {
		// #given
		const message = 'KMS API failed';
		const originalError = new Error('Network timeout');

		// #when
		const error = new KmsClientError(message, originalError);

		// #then
		expect(error).toBeInstanceOf(KmsClientError);
		expect(error.name).toBe('KmsClientError');
		expect(error.message).toBe(message);
		expect(error.cause).toBe(originalError);
	});

	test('should handle undefined cause explicitly', () => {
		// #given
		const message = 'KMS API failed';

		// #when
		const error = new KmsClientError(message, undefined);

		// #then
		expect(error.cause).toBeUndefined();
	});
});

describe('SignatureNormalizationError', () => {
	test('should create error with correct name and message', () => {
		// #given
		const message = 's value out of range';

		// #when
		const error = new SignatureNormalizationError(message);

		// #then
		expect(error).toBeInstanceOf(Error);
		expect(error).toBeInstanceOf(KmsSignerError);
		expect(error).toBeInstanceOf(SignatureNormalizationError);
		expect(error.name).toBe('SignatureNormalizationError');
		expect(error.message).toBe(message);
	});
});

describe('RecoveryIdCalculationError', () => {
	test('should create error with correct name and message', () => {
		// #given
		const message = 'Cannot find valid recovery ID';

		// #when
		const error = new RecoveryIdCalculationError(message);

		// #then
		expect(error).toBeInstanceOf(Error);
		expect(error).toBeInstanceOf(KmsSignerError);
		expect(error).toBeInstanceOf(RecoveryIdCalculationError);
		expect(error.name).toBe('RecoveryIdCalculationError');
		expect(error.message).toBe(message);
	});
});
