import { type Address, keccak256, toHex } from 'viem';
import { DerParsingError } from '../errors/index.js';

/**
 * Extract uncompressed public key from DER-encoded SubjectPublicKeyInfo
 *
 * AWS KMS returns public keys in SubjectPublicKeyInfo (SPKI) format:
 * SEQUENCE (algorithm identifier + public key bit string)
 *
 * For secp256k1, the last 65 bytes are the uncompressed public key:
 * 0x04 (uncompressed marker) + 32-byte x coordinate + 32-byte y coordinate
 *
 * @param der - DER-encoded public key from AWS KMS GetPublicKeyCommand
 * @returns 65-byte uncompressed public key (0x04 + x + y)
 * @throws DerParsingError if public key format is invalid
 */
export function extractPublicKeyFromDer(der: Uint8Array): Uint8Array {
	// Validate minimum length
	if (der.length === 0) {
		throw new DerParsingError('Invalid DER: empty buffer');
	}

	if (der.length < 65) {
		throw new DerParsingError(
			`Invalid DER: buffer too short (expected at least 65 bytes, got ${der.length})`,
		);
	}

	// Simple implementation: last 65 bytes are the public key
	// (0x04 + x coordinate 32 bytes + y coordinate 32 bytes)
	const publicKey = der.slice(-65);

	if (publicKey[0] !== 0x04) {
		throw new DerParsingError(
			`Invalid public key format: expected uncompressed (0x04), got 0x${publicKey[0].toString(16).padStart(2, '0')}`,
		);
	}

	return publicKey;
}

/**
 * Convert uncompressed public key to Ethereum address
 *
 * Ethereum address derivation:
 * 1. Remove 0x04 prefix from public key (keep only x and y coordinates)
 * 2. Hash the 64-byte coordinate data with keccak256
 * 3. Take the last 20 bytes of the hash
 * 4. Format as 0x-prefixed hex string (checksummed)
 *
 * @param publicKey - 65-byte uncompressed public key (0x04 + x + y)
 * @returns Ethereum address (0x-prefixed, 40 hex chars)
 */
export function publicKeyToAddress(publicKey: Uint8Array): Address {
	// Validate public key length
	if (publicKey.length === 0) {
		throw new DerParsingError('Invalid public key: empty buffer');
	}

	if (publicKey.length < 65) {
		throw new DerParsingError(
			`Invalid public key: expected at least 65 bytes, got ${publicKey.length}`,
		);
	}

	// Remove 0x04 prefix, hash only x and y coordinates
	const publicKeyWithoutPrefix = publicKey.slice(1);

	// Calculate keccak256 hash
	const hash = keccak256(toHex(publicKeyWithoutPrefix));

	// Last 20 bytes = Ethereum address
	const address = `0x${hash.slice(-40)}` as Address;

	return address;
}
