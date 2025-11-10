import { describe, test, expect } from 'vitest'
import { normalizeS, calculateV, uint8ArrayToBigInt, SECP256K1_N, SECP256K1_N_HALF } from './signature'
import { SignatureNormalizationError, RecoveryIdCalculationError } from '../errors'

describe('normalizeS', () => {
  test('should normalize s when s > n/2', () => {
    // #given
    // s value in upper half of curve order
    const s = SECP256K1_N_HALF + 1n

    // #when
    const normalized = normalizeS(s)

    // #then
    expect(normalized).toBeLessThanOrEqual(SECP256K1_N_HALF)
    expect(normalized).toBe(SECP256K1_N - s)
  })

  test('should keep s unchanged when s <= n/2', () => {
    // #given
    // s value in lower half of curve order
    const s = SECP256K1_N_HALF - 1n

    // #when
    const normalized = normalizeS(s)

    // #then
    expect(normalized).toBe(s)
  })

  test('should keep s unchanged when s = n/2', () => {
    // #given
    const s = SECP256K1_N_HALF

    // #when
    const normalized = normalizeS(s)

    // #then
    expect(normalized).toBe(s)
  })

  test('should throw SignatureNormalizationError when s <= 0', () => {
    // #given
    const s = 0n

    // #when & #then
    expect(() => normalizeS(s)).toThrow(SignatureNormalizationError)
    expect(() => normalizeS(s)).toThrow('s value out of valid range')
  })

  test('should throw SignatureNormalizationError when s >= n', () => {
    // #given
    const s = SECP256K1_N

    // #when & #then
    expect(() => normalizeS(s)).toThrow(SignatureNormalizationError)
    expect(() => normalizeS(s)).toThrow('s value out of valid range')
  })

  test('should throw SignatureNormalizationError when s is negative', () => {
    // #given
    const s = -1n

    // #when & #then
    expect(() => normalizeS(s)).toThrow(SignatureNormalizationError)
  })
})

describe('calculateV', () => {
  test('should calculate legacy v value (27) for recoveryId 0', () => {
    // #given
    const recoveryId = 0

    // #when
    const v = calculateV(recoveryId)

    // #then
    expect(v).toBe(27n)
  })

  test('should calculate legacy v value (28) for recoveryId 1', () => {
    // #given
    const recoveryId = 1

    // #when
    const v = calculateV(recoveryId)

    // #then
    expect(v).toBe(28n)
  })

  test('should calculate EIP-155 v value for chainId 1 and recoveryId 0', () => {
    // #given
    const recoveryId = 0
    const chainId = 1

    // #when
    const v = calculateV(recoveryId, chainId)

    // #then
    // v = chainId * 2 + 35 + recoveryId = 1 * 2 + 35 + 0 = 37
    expect(v).toBe(37n)
  })

  test('should calculate EIP-155 v value for chainId 1 and recoveryId 1', () => {
    // #given
    const recoveryId = 1
    const chainId = 1

    // #when
    const v = calculateV(recoveryId, chainId)

    // #then
    // v = chainId * 2 + 35 + recoveryId = 1 * 2 + 35 + 1 = 38
    expect(v).toBe(38n)
  })

  test('should calculate EIP-155 v value for chainId 137 (Polygon)', () => {
    // #given
    const recoveryId = 0
    const chainId = 137

    // #when
    const v = calculateV(recoveryId, chainId)

    // #then
    // v = chainId * 2 + 35 + recoveryId = 137 * 2 + 35 + 0 = 309
    expect(v).toBe(309n)
  })

  test('should throw RecoveryIdCalculationError when recoveryId < 0', () => {
    // #given
    const recoveryId = -1

    // #when & #then
    expect(() => calculateV(recoveryId)).toThrow(RecoveryIdCalculationError)
    expect(() => calculateV(recoveryId)).toThrow('Invalid recovery ID')
  })

  test('should throw RecoveryIdCalculationError when recoveryId > 3', () => {
    // #given
    const recoveryId = 4

    // #when & #then
    expect(() => calculateV(recoveryId)).toThrow(RecoveryIdCalculationError)
    expect(() => calculateV(recoveryId)).toThrow('Invalid recovery ID')
  })
})

describe('uint8ArrayToBigInt', () => {
  test('should convert Uint8Array to bigint', () => {
    // #given
    const bytes = new Uint8Array([0x01, 0x02, 0x03, 0x04])

    // #when
    const value = uint8ArrayToBigInt(bytes)

    // #then
    expect(value).toBe(0x01020304n)
  })

  test('should convert single byte Uint8Array to bigint', () => {
    // #given
    const bytes = new Uint8Array([0xff])

    // #when
    const value = uint8ArrayToBigInt(bytes)

    // #then
    expect(value).toBe(0xffn)
  })

  test('should return 0n for empty Uint8Array', () => {
    // #given
    const bytes = new Uint8Array([])

    // #when
    const value = uint8ArrayToBigInt(bytes)

    // #then
    expect(value).toBe(0n)
  })

  test('should convert 32-byte Uint8Array (typical r/s value)', () => {
    // #given
    const bytes = new Uint8Array(32).fill(0x11)

    // #when
    const value = uint8ArrayToBigInt(bytes)

    // #then
    expect(value).toBe(0x1111111111111111111111111111111111111111111111111111111111111111n)
  })

  test('should handle leading zeros correctly', () => {
    // #given
    const bytes = new Uint8Array([0x00, 0x00, 0x01, 0x02])

    // #when
    const value = uint8ArrayToBigInt(bytes)

    // #then
    expect(value).toBe(0x0102n)
  })
})
