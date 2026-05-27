import type { TypedData } from 'abitype';
import type {
	Address,
	Hex,
	SerializeTransactionFn,
	TransactionSerializable,
	TypedDataDefinition,
} from 'viem';
import {
	concat,
	fromHex,
	getTransactionType,
	hashMessage,
	hashTypedData,
	keccak256,
	serializeTransaction,
	toHex,
} from 'viem';
import type { GcpKmsConfig } from '../types';
import { extractPublicKeyFromDer, publicKeyToAddress } from '../utils/address';
import { parseDerSignature } from '../utils/der';
import {
	calculateRecoveryId,
	calculateV,
	calculateYParity,
	normalizeS,
	uint8ArrayToBigInt,
} from '../utils/signature';
import { GcpClient } from './client';

/**
 * GcpSigner provides Ethereum signing capabilities using GCP KMS.
 *
 * This class manages the interaction with GCP KMS for cryptographic operations
 * required by Ethereum accounts:
 * - Public key retrieval and caching
 * - Ethereum address derivation from KMS public key
 * - Message and transaction signing
 *
 * The signer caches expensive operations (public key retrieval, address derivation)
 * to avoid unnecessary KMS API calls.
 *
 * @example
 * ```typescript
 * const signer = new GcpSigner({
 *   projectId: 'my-project',
 *   locationId: 'global',
 *   keyRingId: 'my-keyring',
 *   keyId: 'my-key',
 *   keyVersion: '1'
 * })
 *
 * const address = await signer.getAddress()
 * console.log('Ethereum address:', address)
 * ```
 */
export class GcpSigner {
	private gcpClient: GcpClient;
	private cachedAddress?: Address;
	private cachedPublicKey?: Uint8Array;

	/**
	 * Creates a new GCP KMS signer instance.
	 *
	 * @param config - GCP KMS configuration including project, location, key ring, key, and version
	 *
	 * @remarks
	 * The constructor initializes the GCP KMS client but does not make any API calls.
	 * Public key retrieval and address derivation happen lazily on first use.
	 */
	constructor(config: GcpKmsConfig) {
		this.gcpClient = new GcpClient(config);
	}

	/**
	 * Retrieves the uncompressed secp256k1 public key from GCP KMS.
	 *
	 * The public key is retrieved from KMS and extracted from the DER-encoded
	 * SubjectPublicKeyInfo format. The result is cached to avoid redundant KMS calls.
	 *
	 * @returns 65-byte uncompressed public key (0x04 + x coordinate + y coordinate)
	 * @throws {KmsClientError} If KMS API call fails
	 * @throws {DerParsingError} If public key format is invalid
	 *
	 * @remarks
	 * The public key format is:
	 * - Byte 0: 0x04 (uncompressed point indicator)
	 * - Bytes 1-32: x coordinate of the public key
	 * - Bytes 33-64: y coordinate of the public key
	 */
	async getPublicKey(): Promise<Uint8Array> {
		if (this.cachedPublicKey) {
			return this.cachedPublicKey;
		}

		const derPublicKey = await this.gcpClient.getPublicKey();
		const publicKey = extractPublicKeyFromDer(derPublicKey);
		this.cachedPublicKey = publicKey;
		return publicKey;
	}

	/**
	 * Derives the Ethereum address from the GCP KMS public key.
	 *
	 * The address is calculated by:
	 * 1. Retrieving the public key from KMS (cached if available)
	 * 2. Hashing the public key coordinates with keccak256
	 * 3. Taking the last 20 bytes as the address
	 *
	 * The result is cached to avoid redundant derivation.
	 *
	 * @returns Ethereum address (0x-prefixed, 40 hex characters)
	 * @throws {KmsClientError} If KMS API call fails
	 * @throws {DerParsingError} If public key format is invalid
	 *
	 * @remarks
	 * The returned address follows EIP-55 checksum encoding.
	 */
	async getAddress(): Promise<Address> {
		if (this.cachedAddress) {
			return this.cachedAddress;
		}

		const publicKey = await this.getPublicKey();
		const address = publicKeyToAddress(publicKey);
		this.cachedAddress = address;
		return address;
	}

	/**
	 * Signs a hash using the GCP KMS private key (internal helper method).
	 *
	 * This method is used internally by signMessage, signTransaction, and signTypedData.
	 * It converts the hash to bytes, signs with KMS, parses the DER signature,
	 * and normalizes the s value according to EIP-2.
	 *
	 * @param hash - The hash to sign (32 bytes, hex-encoded)
	 * @returns Object containing r and s as bigints
	 * @throws {KmsClientError} If KMS API call fails
	 * @throws {DerParsingError} If signature format is invalid
	 * @throws {SignatureNormalizationError} If s value is out of valid range
	 *
	 * @remarks
	 * The s value is automatically normalized to the lower half of the curve order (EIP-2)
	 * to prevent signature malleability attacks.
	 */
	private async signHash(hash: Hex): Promise<{ r: bigint; s: bigint }> {
		// Convert Hex to Uint8Array
		const hashBytes = fromHex(hash, 'bytes');

		// Sign with GCP KMS
		const derSignature = await this.gcpClient.sign(hashBytes);

		// Parse DER signature
		const { r: rBytes, s: sBytes } = parseDerSignature(derSignature);

		// Convert to bigint
		const r = uint8ArrayToBigInt(rBytes);
		let s = uint8ArrayToBigInt(sBytes);

		// EIP-2 normalization
		s = normalizeS(s);

		return { r, s };
	}

	/**
	 * Signs a message using EIP-191 personal_sign standard.
	 *
	 * This method:
	 * 1. Hashes the message with EIP-191 prefix: "\x19Ethereum Signed Message:\n" + len(message) + message
	 * 2. Signs the hash with GCP KMS
	 * 3. Calculates the recovery ID to enable public key recovery
	 * 4. Returns the signature in the standard format: r (32 bytes) + s (32 bytes) + v (1 byte)
	 *
	 * @param params - Object containing the message string
	 * @returns The signature as a hex string (0x-prefixed, 130 characters)
	 * @throws {KmsClientError} If KMS API call fails
	 * @throws {DerParsingError} If signature format is invalid
	 * @throws {RecoveryIdCalculationError} If recovery ID calculation fails
	 *
	 * @example
	 * ```typescript
	 * const signer = new GcpSigner({
	 *   projectId: 'my-project',
	 *   locationId: 'global',
	 *   keyRingId: 'my-keyring',
	 *   keyId: 'my-key',
	 *   keyVersion: '1'
	 * })
	 * const signature = await signer.signMessage({ message: 'Hello, world!' })
	 * // signature: '0x...' (130 characters: 0x + 64 hex chars for r + 64 for s + 2 for v)
	 * ```
	 */
	async signMessage({ message }: { message: string }): Promise<Hex> {
		// EIP-191 hashing (viem handles automatically)
		const messageHash = hashMessage(message);

		// Sign with GCP KMS
		const { r, s } = await this.signHash(messageHash);

		// Calculate recovery ID
		const address = await this.getAddress();
		const recoveryId = await calculateRecoveryId(
			messageHash,
			toHex(r, { size: 32 }),
			toHex(s, { size: 32 }),
			address,
		);

		// Calculate v value (Legacy, no chain)
		const v = 27 + recoveryId;

		// Serialize signature
		return concat([
			toHex(r, { size: 32 }),
			toHex(s, { size: 32 }),
			toHex(v, { size: 1 }),
		]) as Hex;
	}

	/**
	 * Signs an Ethereum transaction.
	 *
	 * This method:
	 * 1. Serializes the transaction without signature fields (r, s, v)
	 * 2. Hashes the serialized transaction with keccak256
	 * 3. Signs the hash with GCP KMS
	 * 4. Calculates the recovery ID
	 * 5. Computes the v value (EIP-155 if chainId present, legacy otherwise)
	 * 6. Returns the fully serialized transaction with signature
	 *
	 * @param transaction - The transaction to sign
	 * @param options - Optional serializer function (defaults to viem's serializeTransaction)
	 * @returns The serialized signed transaction as a hex string
	 * @throws {KmsClientError} If KMS API call fails
	 * @throws {DerParsingError} If signature format is invalid
	 * @throws {RecoveryIdCalculationError} If recovery ID calculation fails
	 *
	 * @example
	 * ```typescript
	 * const signer = new GcpSigner({
	 *   projectId: 'my-project',
	 *   locationId: 'global',
	 *   keyRingId: 'my-keyring',
	 *   keyId: 'my-key',
	 *   keyVersion: '1'
	 * })
	 * const signedTx = await signer.signTransaction({
	 *   to: '0x...',
	 *   value: parseEther('1'),
	 *   chainId: 1
	 * })
	 * ```
	 */
	async signTransaction(
		transaction: TransactionSerializable,
		{
			serializer = serializeTransaction,
		}: { serializer?: SerializeTransactionFn } = {},
	): Promise<Hex> {
		// Strip signature-related fields (including yParity) before hashing
		// so the unsigned payload is hashed deterministically regardless of
		// whether the caller left stray fields on the input.
		const serializedTx = serializeTransaction({
			...transaction,
			r: undefined,
			s: undefined,
			v: undefined,
			yParity: undefined,
		});
		const hash = keccak256(serializedTx);

		// Sign with GCP KMS
		const { r, s } = await this.signHash(hash);

		// Calculate recovery ID
		const address = await this.getAddress();
		const recoveryId = await calculateRecoveryId(
			hash,
			toHex(r, { size: 32 }),
			toHex(s, { size: 32 }),
			address,
		);

		// Typed transactions (EIP-2930/1559/4844/7702) require `yParity`.
		// Only legacy (type 0) transactions use the EIP-155 / pre-EIP-155 `v`.
		// The signature must be passed as the second argument to viem's
		// serializer — `serializeTransactionLegacy` ignores r/s/v spread
		// onto the transaction object.
		const transactionType = getTransactionType(transaction);
		const rHex = toHex(r, { size: 32 });
		const sHex = toHex(s, { size: 32 });

		if (transactionType === 'legacy') {
			const chainId = transaction.chainId;
			const v =
				chainId !== undefined
					? calculateV(recoveryId, chainId)
					: calculateV(recoveryId);

			return serializer(transaction, { r: rHex, s: sHex, v });
		}

		return serializer(transaction, {
			r: rHex,
			s: sHex,
			yParity: calculateYParity(recoveryId),
		});
	}

	/**
	 * Signs typed data according to EIP-712.
	 *
	 * This method:
	 * 1. Hashes the typed data using EIP-712 (domain separator + type hash)
	 * 2. Signs the hash with GCP KMS
	 * 3. Calculates the recovery ID
	 * 4. Returns the signature in the standard format: r (32 bytes) + s (32 bytes) + v (1 byte)
	 *
	 * @param typedData - The EIP-712 typed data to sign
	 * @returns The signature as a hex string (0x-prefixed, 130 characters)
	 * @throws {KmsClientError} If KMS API call fails
	 * @throws {DerParsingError} If signature format is invalid
	 * @throws {RecoveryIdCalculationError} If recovery ID calculation fails
	 *
	 * @example
	 * ```typescript
	 * const signer = new GcpSigner({
	 *   projectId: 'my-project',
	 *   locationId: 'global',
	 *   keyRingId: 'my-keyring',
	 *   keyId: 'my-key',
	 *   keyVersion: '1'
	 * })
	 * const signature = await signer.signTypedData({
	 *   domain: {
	 *     name: 'MyApp',
	 *     version: '1',
	 *     chainId: 1,
	 *     verifyingContract: '0x...'
	 *   },
	 *   types: {
	 *     Person: [
	 *       { name: 'name', type: 'string' },
	 *       { name: 'wallet', type: 'address' }
	 *     ]
	 *   },
	 *   primaryType: 'Person',
	 *   message: {
	 *     name: 'Alice',
	 *     wallet: '0x...'
	 *   }
	 * })
	 * ```
	 */
	async signTypedData<
		const TTypedData extends TypedData | Record<string, unknown>,
		TPrimaryType extends keyof TTypedData | 'EIP712Domain' = keyof TTypedData,
	>(typedData: TypedDataDefinition<TTypedData, TPrimaryType>): Promise<Hex> {
		// EIP-712 hashing (viem handles domain separator and type hash)
		const hash = hashTypedData(typedData);

		// Sign with GCP KMS
		const { r, s } = await this.signHash(hash);

		// Calculate recovery ID
		const address = await this.getAddress();
		const recoveryId = await calculateRecoveryId(
			hash,
			toHex(r, { size: 32 }),
			toHex(s, { size: 32 }),
			address,
		);

		// Calculate v value (Legacy, no chain for typed data)
		const v = 27 + recoveryId;

		// Serialize signature
		return concat([
			toHex(r, { size: 32 }),
			toHex(s, { size: 32 }),
			toHex(v, { size: 1 }),
		]) as Hex;
	}
}
