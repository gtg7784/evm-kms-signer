import type { Hex } from 'viem';
import { concat } from 'viem';
import { KmsSignerError } from '../errors/index.js';
import type { CoSignature } from '../types/index.js';

/**
 * Sorts co-signatures by signer address in ascending order.
 *
 * Safe (Gnosis Safe) multisig requires signatures to be ordered by owner
 * address in strictly ascending order, so duplicate addresses are rejected.
 *
 * @param signatures - Co-signatures to sort
 * @returns A new array sorted by address (ascending)
 * @throws {KmsSignerError} If two signatures share the same signer address
 */
export function sortSignaturesByAddress(
	signatures: CoSignature[],
): CoSignature[] {
	const sorted = [...signatures].sort((a, b) =>
		BigInt(a.address) < BigInt(b.address) ? -1 : 1,
	);

	for (let i = 1; i < sorted.length; i++) {
		if (BigInt(sorted[i - 1].address) === BigInt(sorted[i].address)) {
			throw new KmsSignerError(
				`Duplicate signer address: ${sorted[i].address}`,
			);
		}
	}

	return sorted;
}

/**
 * Packs co-signatures into the format expected by Safe's `execTransaction`.
 *
 * Signatures are sorted by signer address (ascending) and concatenated as
 * r (32 bytes) + s (32 bytes) + v (1 byte) per signer.
 *
 * @param signatures - Co-signatures over the Safe transaction hash (EIP-712 SafeTx)
 * @returns Concatenated signatures as hex
 * @throws {KmsSignerError} If two signatures share the same signer address
 *
 * @example
 * ```typescript
 * const { signatures } = await coSigner.signTypedData(safeTxTypedData)
 * const packed = packSafeSignatures(signatures)
 * // pass `packed` as the `signatures` argument of Safe.execTransaction
 * ```
 */
export function packSafeSignatures(signatures: CoSignature[]): Hex {
	return concat(
		sortSignaturesByAddress(signatures).map(({ signature }) => signature),
	);
}
