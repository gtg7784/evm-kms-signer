import { DerParsingError } from '../errors/index.js';
import type { DerSignature } from '../types/index.js';

/**
 * Parse DER-encoded ECDSA signature into r and s components
 *
 * DER structure:
 * SEQUENCE (0x30) [total_length]
 *   INTEGER (0x02) [r_length] [r_bytes]
 *   INTEGER (0x02) [s_length] [s_bytes]
 *
 * @param der - DER-encoded signature from AWS KMS
 * @returns Object with r and s as 32-byte Uint8Arrays
 * @throws DerParsingError if signature format is invalid
 */
export function parseDerSignature(der: Uint8Array): DerSignature {
	// Validate minimum length
	if (der.length === 0) {
		throw new DerParsingError('Invalid DER signature: empty buffer');
	}

	if (der.length < 8) {
		throw new DerParsingError('Invalid DER signature: buffer too short');
	}

	// Validate SEQUENCE tag
	if (der[0] !== 0x30) {
		throw new DerParsingError(
			'Invalid DER signature: expected SEQUENCE tag (0x30)',
		);
	}

	const sequenceLength = der[1];
	if (der.length < sequenceLength + 2) {
		throw new DerParsingError(
			'Invalid DER signature: SEQUENCE length exceeds buffer size',
		);
	}

	let offset = 2; // Skip SEQUENCE tag and length

	// Parse r INTEGER
	if (offset >= der.length) {
		throw new DerParsingError('Invalid DER signature: missing r INTEGER tag');
	}

	if (der[offset] !== 0x02) {
		throw new DerParsingError(
			'Invalid DER signature: expected INTEGER tag (0x02) for r',
		);
	}
	offset++;

	if (offset >= der.length) {
		throw new DerParsingError('Invalid DER signature: missing r length');
	}

	const rLength = der[offset];
	offset++;

	// Validate r length
	if (rLength === 0) {
		throw new DerParsingError('Invalid DER signature: r length cannot be 0');
	}

	if (rLength > 33) {
		throw new DerParsingError(
			'Invalid DER signature: r length exceeds maximum (33 bytes)',
		);
	}

	if (offset + rLength > der.length) {
		throw new DerParsingError(
			'Invalid DER signature: r value exceeds buffer length',
		);
	}

	let r = der.slice(offset, offset + rLength);
	// Remove leading 0x00 (negative number prevention padding)
	if (rLength === 33 && r[0] === 0x00) {
		r = r.slice(1);
	}
	// Left-pad with zeros to 32 bytes
	if (r.length < 32) {
		const padded = new Uint8Array(32);
		padded.set(r, 32 - r.length);
		r = padded;
	}
	offset += rLength;

	// Parse s INTEGER
	if (offset >= der.length) {
		throw new DerParsingError('Invalid DER signature: missing s INTEGER tag');
	}

	if (der[offset] !== 0x02) {
		throw new DerParsingError(
			'Invalid DER signature: expected INTEGER tag (0x02) for s',
		);
	}
	offset++;

	if (offset >= der.length) {
		throw new DerParsingError('Invalid DER signature: missing s length');
	}

	const sLength = der[offset];
	offset++;

	// Validate s length
	if (sLength === 0) {
		throw new DerParsingError('Invalid DER signature: s length cannot be 0');
	}

	if (sLength > 33) {
		throw new DerParsingError(
			'Invalid DER signature: s length exceeds maximum (33 bytes)',
		);
	}

	if (offset + sLength > der.length) {
		throw new DerParsingError(
			'Invalid DER signature: s value exceeds buffer length',
		);
	}

	let s = der.slice(offset, offset + sLength);
	if (sLength === 33 && s[0] === 0x00) {
		s = s.slice(1);
	}
	if (s.length < 32) {
		const padded = new Uint8Array(32);
		padded.set(s, 32 - s.length);
		s = padded;
	}

	return { r, s };
}
