import type { TypedData } from 'abitype';
import type { Hex, TypedDataDefinition } from 'viem';
import { CoSignThresholdError, KmsSignerError } from '../errors/index.js';
import type {
	CoSignature,
	CoSignerConfig,
	CoSignerMember,
	CoSignFailure,
	CoSignResult,
} from '../types/index.js';
import { sortSignaturesByAddress } from '../utils/safe.js';

/**
 * CoSigner signs the same payload with multiple KMS keys (M-of-N).
 *
 * AWS (KmsSigner) and GCP (GcpSigner) signers can be mixed. All signers are
 * invoked in parallel; the operation succeeds when at least `threshold`
 * signers succeed. Successful signatures are returned sorted by signer
 * address (ascending), which is the order Safe multisig expects.
 *
 * @example
 * ```typescript
 * const coSigner = new CoSigner({
 *   signers: [
 *     new KmsSigner({ region: 'us-east-1', keyId: 'key-1' }),
 *     new KmsSigner({ region: 'us-east-1', keyId: 'key-2' }),
 *     new GcpSigner({ projectId, locationId, keyRingId, keyId, keyVersion }),
 *   ],
 *   threshold: 2,
 * })
 *
 * const { signatures, failures } = await coSigner.signTypedData(safeTxTypedData)
 * const packed = packSafeSignatures(signatures)
 * ```
 */
export class CoSigner {
	private signers: CoSignerMember[];
	private threshold: number;

	/**
	 * Creates a new co-signer instance.
	 *
	 * @param config - Signers and optional threshold (defaults to all signers)
	 * @throws {KmsSignerError} If signers is empty or threshold is not an integer in 1..signers.length
	 */
	constructor(config: CoSignerConfig) {
		const threshold = config.threshold ?? config.signers.length;

		if (config.signers.length === 0) {
			throw new KmsSignerError('CoSigner requires at least one signer');
		}

		if (
			!Number.isInteger(threshold) ||
			threshold < 1 ||
			threshold > config.signers.length
		) {
			throw new KmsSignerError(
				`Invalid threshold (must be an integer between 1 and ${config.signers.length}): ${threshold}`,
			);
		}

		this.signers = config.signers;
		this.threshold = threshold;
	}

	/**
	 * Returns the addresses of all signers, in the order they were configured.
	 *
	 * @returns Ethereum addresses of the signers
	 * @throws {KmsClientError} If KMS API call fails
	 */
	async getAddresses(): Promise<CoSignature['address'][]> {
		return Promise.all(this.signers.map((signer) => signer.getAddress()));
	}

	/**
	 * Signs a message (EIP-191) with every signer.
	 *
	 * @param params - Object containing the message string
	 * @returns Signatures sorted by address and failed signers
	 * @throws {CoSignThresholdError} If fewer than `threshold` signers succeed
	 */
	async signMessage({ message }: { message: string }): Promise<CoSignResult> {
		return this.coSign((signer) => signer.signMessage({ message }));
	}

	/**
	 * Signs EIP-712 typed data with every signer.
	 *
	 * For Safe multisig, pass the SafeTx typed data and combine the result
	 * with `packSafeSignatures()`.
	 *
	 * @param typedData - The EIP-712 typed data to sign
	 * @returns Signatures sorted by address and failed signers
	 * @throws {CoSignThresholdError} If fewer than `threshold` signers succeed
	 */
	async signTypedData<
		const TTypedData extends TypedData | Record<string, unknown>,
		TPrimaryType extends keyof TTypedData | 'EIP712Domain' = keyof TTypedData,
	>(
		typedData: TypedDataDefinition<TTypedData, TPrimaryType>,
	): Promise<CoSignResult> {
		return this.coSign((signer) => signer.signTypedData(typedData));
	}

	private async coSign(
		sign: (signer: CoSignerMember) => Promise<Hex>,
	): Promise<CoSignResult> {
		const results = await Promise.allSettled(
			this.signers.map(async (signer) => ({
				address: await signer.getAddress(),
				signature: await sign(signer),
			})),
		);

		const signatures: CoSignature[] = [];
		const failures: CoSignFailure[] = [];

		results.forEach((result, signerIndex) => {
			if (result.status === 'fulfilled') {
				signatures.push(result.value);
			} else {
				failures.push({
					signerIndex,
					error:
						result.reason instanceof Error
							? result.reason
							: new Error(String(result.reason)),
				});
			}
		});

		if (signatures.length < this.threshold) {
			throw new CoSignThresholdError(
				`Co-signing failed: ${signatures.length} of ${this.signers.length} signers succeeded (threshold ${this.threshold})`,
				failures,
			);
		}

		return { signatures: sortSignaturesByAddress(signatures), failures };
	}
}
