// Main classes and functions

// Re-export commonly used viem types for convenience
export type { Address, Hex } from 'viem';
export { toKmsAccount } from './account';
// Errors
export {
	DerParsingError,
	KmsClientError,
	KmsSignerError,
	RecoveryIdCalculationError,
	SignatureNormalizationError,
} from './errors';
export { KmsSigner } from './kms/signer';
// Types
export type { DerSignature, KmsConfig, SignatureData } from './types';
