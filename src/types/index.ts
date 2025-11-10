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
