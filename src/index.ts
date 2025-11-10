// Main classes and functions
export { KmsSigner } from './kms/signer'
export { toKmsAccount } from './account'

// Types
export type { KmsConfig, DerSignature, SignatureData } from './types'

// Errors
export {
  KmsSignerError,
  DerParsingError,
  KmsClientError,
  SignatureNormalizationError,
  RecoveryIdCalculationError
} from './errors'

// Re-export commonly used viem types for convenience
export type { Address, Hex } from 'viem'
