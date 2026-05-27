import type { Address, Hex } from 'viem';
import { fromHex, recoverPublicKey } from 'viem';
import {
	RecoveryIdCalculationError,
	SignatureNormalizationError,
} from '../errors/index.js';
import { publicKeyToAddress } from './address.js';

/**
 * secp256k1 curve order (n)
 * Maximum value for ECDSA signature components r and s
 */
export const SECP256K1_N =
	0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/**
 * Half of secp256k1 curve order
 * Used for EIP-2 signature normalization
 */
export const SECP256K1_N_HALF = SECP256K1_N / 2n;

/**
 * Normalizes the s value of an ECDSA signature according to EIP-2.
 *
 * EIP-2 requires that s must be in the lower half of the curve order
 * to prevent signature malleability attacks. If s > n/2, it is converted
 * to s' = n - s.
 *
 * @param s - The s component of the ECDSA signature
 * @returns The normalized s value
 * @throws {SignatureNormalizationError} If s is out of valid range
 *
 * @example
 * ```typescript
 * const s = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000001n
 * const normalizedS = normalizeS(s)
 * // normalizedS will be less than SECP256K1_N_HALF
 * ```
 */
export function normalizeS(s: bigint): bigint {
	if (s <= 0n || s >= SECP256K1_N) {
		throw new SignatureNormalizationError(
			`s value out of valid range (must be 0 < s < n): ${s.toString(16)}`,
		);
	}

	if (s > SECP256K1_N_HALF) {
		return SECP256K1_N - s;
	}

	return s;
}

/**
 * Calculates the recovery ID (0-3) for an ECDSA signature.
 *
 * The recovery ID is needed to recover the public key from a signature.
 * This function tries all 4 possible recovery IDs and returns the one
 * that produces a public key matching the expected address.
 *
 * @param messageHash - The hash of the signed message (32 bytes)
 * @param r - The r component of the signature as hex string
 * @param s - The s component of the signature as hex string
 * @param expectedAddress - The expected Ethereum address
 * @returns The recovery ID (0, 1, 2, or 3)
 * @throws {RecoveryIdCalculationError} If no valid recovery ID is found
 *
 * @example
 * ```typescript
 * const recoveryId = await calculateRecoveryId(
 *   '0x1234...', // message hash
 *   '0xabcd...', // r value
 *   '0xef01...', // s value
 *   '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb'
 * )
 * // recoveryId will be 0, 1, 2, or 3
 * ```
 */
export async function calculateRecoveryId(
	messageHash: Hex,
	r: Hex,
	s: Hex,
	expectedAddress: Address,
): Promise<number> {
	for (let recoveryId = 0; recoveryId < 4; recoveryId++) {
		try {
			// Attempt to recover public key using this recovery ID
			// Use legacy v value (27 + recoveryId) for recovery
			const publicKey = await recoverPublicKey({
				hash: messageHash,
				signature: {
					r,
					s,
					v: BigInt(27 + recoveryId),
				},
			});

			// Calculate address from recovered public key
			// recoverPublicKey returns Hex, convert to Uint8Array for publicKeyToAddress
			const publicKeyBytes = fromHex(publicKey, 'bytes');
			const address = publicKeyToAddress(publicKeyBytes);

			// Compare with expected address (case-insensitive)
			if (address.toLowerCase() === expectedAddress.toLowerCase()) {
				return recoveryId;
			}
		} catch {}
	}

	throw new RecoveryIdCalculationError(
		`Cannot find valid recovery ID for signature (r=${r}, s=${s}) and address ${expectedAddress}`,
	);
}

/**
 * Calculates the v value for an ECDSA signature.
 *
 * The v value is used in Ethereum signatures to enable public key recovery.
 * - Legacy (no chainId): v = 27 + recoveryId
 * - EIP-155 (with chainId): v = chainId * 2 + 35 + recoveryId
 *
 * @param recoveryId - The recovery ID (0-3)
 * @param chainId - Optional chain ID for EIP-155 signatures
 * @returns The v value as bigint
 *
 * @remarks
 * This is only valid for legacy (type 0) transactions and EIP-191 / EIP-712
 * signatures. Typed transactions (EIP-2930, EIP-1559, EIP-4844, EIP-7702)
 * encode the parity bit as `yParity`, not as an EIP-155 `v`. Use
 * {@link calculateYParity} for those.
 *
 * @example
 * ```typescript
 * // Legacy signature (no chain ID)
 * const vLegacy = calculateV(0) // returns 27n
 *
 * // EIP-155 signature (with chain ID 1 for Ethereum mainnet)
 * const vEIP155 = calculateV(0, 1) // returns 37n (1 * 2 + 35 + 0)
 * ```
 */
export function calculateV(recoveryId: number, chainId?: number): bigint {
	if (recoveryId < 0 || recoveryId > 3) {
		throw new RecoveryIdCalculationError(
			`Invalid recovery ID (must be 0-3): ${recoveryId}`,
		);
	}

	if (chainId !== undefined) {
		// EIP-155: v = chainId * 2 + 35 + recoveryId
		return BigInt(chainId * 2 + 35 + recoveryId);
	}

	// Legacy: v = 27 + recoveryId
	return BigInt(27 + recoveryId);
}

/**
 * Calculates the yParity value for a typed transaction signature.
 *
 * Typed Ethereum transactions (EIP-2930, EIP-1559, EIP-4844, EIP-7702) encode
 * the recovery bit as `yParity` (0 or 1) instead of the legacy EIP-155 `v`.
 * The yParity is derived from the recovery id modulo 2.
 *
 * @param recoveryId - The recovery ID (0-3)
 * @returns The yParity value (0 or 1)
 * @throws {RecoveryIdCalculationError} If recoveryId is out of range
 *
 * @example
 * ```typescript
 * calculateYParity(0) // returns 0
 * calculateYParity(1) // returns 1
 * calculateYParity(2) // returns 0
 * calculateYParity(3) // returns 1
 * ```
 */
export function calculateYParity(recoveryId: number): 0 | 1 {
	if (recoveryId < 0 || recoveryId > 3) {
		throw new RecoveryIdCalculationError(
			`Invalid recovery ID (must be 0-3): ${recoveryId}`,
		);
	}

	return (recoveryId % 2) as 0 | 1;
}

/**
 * Converts a Uint8Array to a bigint.
 *
 * This is useful for converting DER-encoded signature components
 * (which are returned as Uint8Array) to bigint for cryptographic operations.
 *
 * @param arr - The Uint8Array to convert
 * @returns The bigint representation
 *
 * @example
 * ```typescript
 * const bytes = new Uint8Array([0x01, 0x02, 0x03, 0x04])
 * const value = uint8ArrayToBigInt(bytes)
 * // value === 0x01020304n
 * ```
 */
export function uint8ArrayToBigInt(arr: Uint8Array): bigint {
	if (arr.length === 0) {
		return 0n;
	}

	// Convert Uint8Array to hex string
	const hex = Array.from(arr)
		.map((byte) => byte.toString(16).padStart(2, '0'))
		.join('');

	// Parse as bigint
	return BigInt(`0x${hex}`);
}
