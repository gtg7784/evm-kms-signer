import type { DerSignature } from '../types'
import { DerParsingError } from '../errors'

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
  // Validate SEQUENCE tag
  if (der[0] !== 0x30) {
    throw new DerParsingError('Invalid DER signature: expected SEQUENCE tag (0x30)')
  }

  let offset = 2 // Skip SEQUENCE tag and length

  // Parse r INTEGER
  if (der[offset] !== 0x02) {
    throw new DerParsingError('Invalid DER signature: expected INTEGER tag (0x02) for r')
  }
  offset++
  let rLength = der[offset]
  offset++

  let r = der.slice(offset, offset + rLength)
  // Remove leading 0x00 (negative number prevention padding)
  if (rLength === 33 && r[0] === 0x00) {
    r = r.slice(1)
  }
  // Left-pad with zeros to 32 bytes
  if (r.length < 32) {
    const padded = new Uint8Array(32)
    padded.set(r, 32 - r.length)
    r = padded
  }
  offset += rLength

  // Parse s INTEGER (same logic)
  if (der[offset] !== 0x02) {
    throw new DerParsingError('Invalid DER signature: expected INTEGER tag (0x02) for s')
  }
  offset++
  let sLength = der[offset]
  offset++

  let s = der.slice(offset, offset + sLength)
  if (sLength === 33 && s[0] === 0x00) {
    s = s.slice(1)
  }
  if (s.length < 32) {
    const padded = new Uint8Array(32)
    padded.set(s, 32 - s.length)
    s = padded
  }

  return { r, s }
}
