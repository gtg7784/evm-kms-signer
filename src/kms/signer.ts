import type { Address, Hex } from 'viem'
import { fromHex, toHex, hashMessage, concat } from 'viem'
import { KmsClient } from './client'
import { extractPublicKeyFromDer, publicKeyToAddress } from '../utils/address'
import { parseDerSignature } from '../utils/der'
import { normalizeS, calculateRecoveryId, uint8ArrayToBigInt } from '../utils/signature'
import type { KmsConfig } from '../types'

/**
 * KmsSigner provides Ethereum signing capabilities using AWS KMS.
 *
 * This class manages the interaction with AWS KMS for cryptographic operations
 * required by Ethereum accounts:
 * - Public key retrieval and caching
 * - Ethereum address derivation from KMS public key
 * - Message and transaction signing (to be implemented in Part 2)
 *
 * The signer caches expensive operations (public key retrieval, address derivation)
 * to avoid unnecessary KMS API calls.
 *
 * @example
 * ```typescript
 * const signer = new KmsSigner({
 *   region: 'us-east-1',
 *   keyId: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
 * })
 *
 * const address = await signer.getAddress()
 * console.log('Ethereum address:', address)
 * ```
 */
export class KmsSigner {
  private kmsClient: KmsClient
  private keyId: string
  private cachedAddress?: Address
  private cachedPublicKey?: Uint8Array

  /**
   * Creates a new KMS signer instance.
   *
   * @param config - KMS configuration including region, keyId, and optional credentials
   *
   * @remarks
   * The constructor initializes the KMS client but does not make any API calls.
   * Public key retrieval and address derivation happen lazily on first use.
   */
  constructor(config: KmsConfig) {
    this.kmsClient = new KmsClient(config)
    this.keyId = config.keyId
  }

  /**
   * Retrieves the uncompressed secp256k1 public key from AWS KMS.
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
      return this.cachedPublicKey
    }

    const derPublicKey = await this.kmsClient.getPublicKey()
    const publicKey = extractPublicKeyFromDer(derPublicKey)
    this.cachedPublicKey = publicKey
    return publicKey
  }

  /**
   * Derives the Ethereum address from the KMS public key.
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
      return this.cachedAddress
    }

    const publicKey = await this.getPublicKey()
    const address = publicKeyToAddress(publicKey)
    this.cachedAddress = address
    return address
  }

  /**
   * Signs a hash using the KMS private key (internal helper method).
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
    const hashBytes = fromHex(hash, 'bytes')

    // Sign with KMS
    const derSignature = await this.kmsClient.sign(hashBytes)

    // Parse DER signature
    const { r: rBytes, s: sBytes } = parseDerSignature(derSignature)

    // Convert to bigint
    let r = uint8ArrayToBigInt(rBytes)
    let s = uint8ArrayToBigInt(sBytes)

    // EIP-2 normalization
    s = normalizeS(s)

    return { r, s }
  }

  /**
   * Signs a message using EIP-191 personal_sign standard.
   *
   * This method:
   * 1. Hashes the message with EIP-191 prefix: "\x19Ethereum Signed Message:\n" + len(message) + message
   * 2. Signs the hash with KMS
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
   * const signer = new KmsSigner({ region: 'us-east-1', keyId: 'arn:...' })
   * const signature = await signer.signMessage({ message: 'Hello, world!' })
   * // signature: '0x...' (130 characters: 0x + 64 hex chars for r + 64 for s + 2 for v)
   * ```
   */
  async signMessage({ message }: { message: string }): Promise<Hex> {
    // EIP-191 hashing (viem handles automatically)
    const messageHash = hashMessage(message)

    // Sign with KMS
    const { r, s } = await this.signHash(messageHash)

    // Calculate recovery ID
    const address = await this.getAddress()
    const recoveryId = await calculateRecoveryId(
      messageHash,
      toHex(r, { size: 32 }),
      toHex(s, { size: 32 }),
      address
    )

    // Calculate v value (Legacy, no chain)
    const v = 27 + recoveryId

    // Serialize signature
    return concat([
      toHex(r, { size: 32 }),
      toHex(s, { size: 32 }),
      toHex(v, { size: 1 })
    ]) as Hex
  }
}
