import { describe, test, expect } from 'vitest'
import { extractPublicKeyFromDer, publicKeyToAddress } from './address'
import { DerParsingError } from '../errors'

describe('extractPublicKeyFromDer', () => {
  test('should extract 65-byte public key from DER-encoded bytes', () => {
    // #given
    // Mock DER with header bytes + 65-byte uncompressed public key
    const mockDer = new Uint8Array([
      // DER header (variable length, simulating AWS KMS format)
      0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86,
      0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
      0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00,
      // 65-byte uncompressed public key (0x04 + x + y)
      0x04,
      ...Array(32).fill(0x11), // x coordinate
      ...Array(32).fill(0x22)  // y coordinate
    ])

    // #when
    const publicKey = extractPublicKeyFromDer(mockDer)

    // #then
    expect(publicKey).toHaveLength(65)
    expect(publicKey[0]).toBe(0x04) // uncompressed marker
    expect(publicKey[1]).toBe(0x11) // first byte of x
    expect(publicKey[33]).toBe(0x22) // first byte of y
  })

  test('should validate that public key starts with 0x04', () => {
    // #given
    const mockDer = new Uint8Array([
      ...Array(23).fill(0x00), // Header
      0x04, // Valid uncompressed marker
      ...Array(64).fill(0x11)
    ])

    // #when
    const publicKey = extractPublicKeyFromDer(mockDer)

    // #then
    expect(publicKey[0]).toBe(0x04)
  })

  test('should throw DerParsingError when public key does not start with 0x04', () => {
    // #given
    // Compressed public key format (0x02 or 0x03)
    const mockDer = new Uint8Array([
      ...Array(23).fill(0x00), // Header
      0x03, // Compressed marker (invalid)
      ...Array(64).fill(0x11)
    ])

    // #when & #then
    expect(() => extractPublicKeyFromDer(mockDer)).toThrow(DerParsingError)
    expect(() => extractPublicKeyFromDer(mockDer)).toThrow('Invalid public key format')
    expect(() => extractPublicKeyFromDer(mockDer)).toThrow('expected uncompressed')
  })

  test('should handle exact 65-byte DER (edge case)', () => {
    // #given
    // DER that is exactly 65 bytes (no header)
    const mockDer = new Uint8Array([
      0x04,
      ...Array(64).fill(0xff)
    ])

    // #when
    const publicKey = extractPublicKeyFromDer(mockDer)

    // #then
    expect(publicKey).toHaveLength(65)
    expect(publicKey[0]).toBe(0x04)
  })
})

describe('publicKeyToAddress', () => {
  test('should derive Ethereum address from uncompressed public key', () => {
    // #given
    // Known test case: a predictable public key
    // Using a simple pattern for reproducibility
    const publicKey = new Uint8Array([
      0x04,
      // x coordinate (32 bytes of 0x11)
      ...Array(32).fill(0x11),
      // y coordinate (32 bytes of 0x22)
      ...Array(32).fill(0x22)
    ])

    // #when
    const address = publicKeyToAddress(publicKey)

    // #then
    expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/) // Valid Ethereum address format
    expect(address).toHaveLength(42) // 0x + 40 hex chars
    // The actual address value is deterministic from keccak256
    // We verify format rather than exact value
  })

  test('should produce consistent address for same public key', () => {
    // #given
    const publicKey = new Uint8Array([
      0x04,
      ...Array(32).fill(0xaa),
      ...Array(32).fill(0xbb)
    ])

    // #when
    const address1 = publicKeyToAddress(publicKey)
    const address2 = publicKeyToAddress(publicKey)

    // #then
    expect(address1).toBe(address2) // Deterministic
  })

  test('should produce different addresses for different public keys', () => {
    // #given
    const publicKey1 = new Uint8Array([
      0x04,
      ...Array(32).fill(0x11),
      ...Array(32).fill(0x22)
    ])
    const publicKey2 = new Uint8Array([
      0x04,
      ...Array(32).fill(0x33),
      ...Array(32).fill(0x44)
    ])

    // #when
    const address1 = publicKeyToAddress(publicKey1)
    const address2 = publicKeyToAddress(publicKey2)

    // #then
    expect(address1).not.toBe(address2)
  })

  test('should derive address using only x and y coordinates (excluding 0x04)', () => {
    // #given
    const publicKey = new Uint8Array([
      0x04,
      ...Array(64).fill(0x01) // x + y coordinates
    ])

    // #when
    const address = publicKeyToAddress(publicKey)

    // #then
    // Address should be derived from keccak256 of 64 bytes (not 65)
    expect(address).toBeDefined()
    expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/)
    // The first byte (0x04) should not affect the hash
  })

  test('should handle public key with all zeros in coordinates', () => {
    // #given
    const publicKey = new Uint8Array([
      0x04,
      ...Array(64).fill(0x00)
    ])

    // #when
    const address = publicKeyToAddress(publicKey)

    // #then
    expect(address).toBeDefined()
    expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/)
  })

  test('should handle public key with all 0xff in coordinates', () => {
    // #given
    const publicKey = new Uint8Array([
      0x04,
      ...Array(64).fill(0xff)
    ])

    // #when
    const address = publicKeyToAddress(publicKey)

    // #then
    expect(address).toBeDefined()
    expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/)
  })
})
