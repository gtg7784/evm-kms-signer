export class KmsSignerError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'KmsSignerError';
	}
}

export class DerParsingError extends KmsSignerError {
	constructor(message: string) {
		super(message);
		this.name = 'DerParsingError';
	}
}

export class KmsClientError extends KmsSignerError {
	constructor(
		message: string,
		public readonly cause?: Error,
	) {
		super(message);
		this.name = 'KmsClientError';
	}
}

export class SignatureNormalizationError extends KmsSignerError {
	constructor(message: string) {
		super(message);
		this.name = 'SignatureNormalizationError';
	}
}

export class RecoveryIdCalculationError extends KmsSignerError {
	constructor(message: string) {
		super(message);
		this.name = 'RecoveryIdCalculationError';
	}
}
