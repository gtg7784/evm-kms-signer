import type { Address, Hex } from 'viem';
import type { KmsSigner } from '../kms/signer.js';

/**
 * AWS KMS configuration for signing operations
 */
export interface KmsConfig {
	/**
	 * AWS region where the KMS key is located (e.g., "us-east-1")
	 */
	region: string;

	/**
	 * KMS key ID or ARN to use for signing
	 */
	keyId: string;

	/**
	 * Optional AWS credentials. If not provided, AWS SDK will use the default credential chain
	 * (environment variables, IAM roles, etc.)
	 */
	credentials?: {
		accessKeyId: string;
		secretAccessKey: string;
	};
}

/**
 * GCP KMS configuration for signing operations
 */
export interface GcpKmsConfig {
	/**
	 * GCP project ID where the KMS key is located
	 */
	projectId: string;

	/**
	 * GCP location/region (e.g., "global", "us-east1")
	 */
	locationId: string;

	/**
	 * Key ring ID containing the crypto key
	 */
	keyRingId: string;

	/**
	 * Crypto key ID to use for signing
	 */
	keyId: string;

	/**
	 * Crypto key version number (e.g., "1")
	 */
	keyVersion: string;

	/**
	 * Optional path to service account key file.
	 * If not provided, uses GOOGLE_APPLICATION_CREDENTIALS environment variable
	 */
	keyFilename?: string;
}

/**
 * DER-parsed signature as raw byte arrays
 * Used internally by DER parsing utilities
 */
export interface DerSignature {
	/**
	 * r component of ECDSA signature (32 bytes)
	 */
	r: Uint8Array;

	/**
	 * s component of ECDSA signature (32 bytes)
	 */
	s: Uint8Array;
}

/**
 * Ethereum signature with recovery ID
 * Used for final signature serialization
 */
export interface SignatureData {
	/**
	 * r component of ECDSA signature as bigint
	 */
	r: bigint;

	/**
	 * s component of ECDSA signature as bigint (after EIP-2 normalization)
	 */
	s: bigint;

	/**
	 * Recovery ID as bigint
	 * - 27-28 for legacy signatures
	 * - 35+ for EIP-155 signatures (includes chain ID)
	 */
	v: bigint;
}

/**
 * A signer that can participate in co-signing.
 * Both KmsSigner and GcpSigner satisfy this shape.
 */
export type CoSignerMember = Pick<
	KmsSigner,
	'getAddress' | 'signMessage' | 'signTypedData'
>;

/**
 * Co-signer configuration
 */
export interface CoSignerConfig {
	/**
	 * Signers that sign the same payload (AWS and GCP signers can be mixed)
	 */
	signers: CoSignerMember[];

	/**
	 * Minimum number of successful signatures required.
	 * Defaults to signers.length (all signers must sign).
	 */
	threshold?: number;
}

/**
 * Signature produced by a single co-signer
 */
export interface CoSignature {
	/**
	 * Address of the signer that produced the signature
	 */
	address: Address;

	/**
	 * Signature in r (32 bytes) + s (32 bytes) + v (1 byte) format
	 */
	signature: Hex;
}

/**
 * Signer that failed to sign during co-signing
 */
export interface CoSignFailure {
	/**
	 * Index of the failed signer in CoSignerConfig.signers
	 */
	signerIndex: number;

	/**
	 * Error thrown by the signer
	 */
	error: Error;
}

/**
 * Result of a co-signing operation
 */
export interface CoSignResult {
	/**
	 * Successful signatures, sorted by signer address in ascending order
	 */
	signatures: CoSignature[];

	/**
	 * Signers that failed (only possible when threshold < signers.length)
	 */
	failures: CoSignFailure[];
}
