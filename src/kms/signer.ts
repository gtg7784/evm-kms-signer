import type { Address } from 'viem'
import { KmsClient } from './client'
import { extractPublicKeyFromDer, publicKeyToAddress } from '../utils/address'
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
}
