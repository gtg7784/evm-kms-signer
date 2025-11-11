// Main classes and functions

// Re-export commonly used viem types for convenience
export type { Address, Hex } from 'viem';
export { toGcpKmsAccount, toKmsAccount } from './account';
// Errors
export {
	DerParsingError,
	KmsClientError,
	KmsSignerError,
	RecoveryIdCalculationError,
	SignatureNormalizationError,
} from './errors';
export { GcpSigner } from './gcp/signer';
export { KmsSigner } from './kms/signer';
// Types
export type {
	DerSignature,
	GcpKmsConfig,
	KmsConfig,
	SignatureData,
} from './types';
