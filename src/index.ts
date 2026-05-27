// Main classes and functions

// Re-export commonly used viem types for convenience
export type { Address, Hex } from 'viem';
export { toGcpKmsAccount, toKmsAccount } from './account.js';
// Errors
export {
	DerParsingError,
	KmsClientError,
	KmsSignerError,
	RecoveryIdCalculationError,
	SignatureNormalizationError,
} from './errors/index.js';
export { GcpSigner } from './gcp/signer.js';
export { KmsSigner } from './kms/signer.js';
// Types
export type {
	DerSignature,
	GcpKmsConfig,
	KmsConfig,
	SignatureData,
} from './types/index.js';
