import type { Hex } from 'viem';
import {
	fromHex,
	hashTypedData,
	recoverAddress,
	size,
	slice,
	toHex,
	verifyMessage,
	zeroAddress,
} from 'viem';
import {
	generatePrivateKey,
	privateKeyToAccount,
	sign as viemSign,
} from 'viem/accounts';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import {
	CoSignThresholdError,
	KmsClientError,
	KmsSignerError,
} from '../errors/index.js';
import { GcpClient } from '../gcp/client.js';
import { GcpSigner } from '../gcp/signer.js';
import { KmsClient } from '../kms/client.js';
import { KmsSigner } from '../kms/signer.js';
import { packSafeSignatures } from '../utils/safe.js';
import { CoSigner } from './signer.js';

vi.mock('../kms/client.js', () => ({ KmsClient: vi.fn() }));
vi.mock('../gcp/client.js', () => ({ GcpClient: vi.fn() }));

const BROKEN_KEY_ID = 'broken-key';

// ASN.1 DER encoder for a secp256k1 ECDSA signature, mirroring KMS output.
function encodeDerInteger(value: Hex): Uint8Array {
	let body = fromHex(value, 'bytes');
	let start = 0;
	while (start < body.length - 1 && body[start] === 0) start++;
	body = body.slice(start);
	if ((body[0] & 0x80) !== 0) {
		body = new Uint8Array([0x00, ...body]);
	}
	return new Uint8Array([0x02, body.length, ...body]);
}

function encodeDerSignature(r: Hex, s: Hex): Uint8Array {
	const content = new Uint8Array([
		...encodeDerInteger(r),
		...encodeDerInteger(s),
	]);
	return new Uint8Array([0x30, content.length, ...content]);
}

function createFakeKmsClient(privateKeys: Map<string, Hex>) {
	return function (
		this: {
			getPublicKey: () => Promise<Uint8Array>;
			sign: (hash: Uint8Array) => Promise<Uint8Array>;
		},
		config: { keyId: string },
	) {
		const privateKey = privateKeys.get(config.keyId) ?? generatePrivateKey();
		this.getPublicKey = async () =>
			fromHex(privateKeyToAccount(privateKey).publicKey, 'bytes');
		this.sign = async (hash: Uint8Array) => {
			if (config.keyId === BROKEN_KEY_ID) {
				throw new KmsClientError('KMS sign failed');
			}
			const { r, s } = await viemSign({
				hash: toHex(hash),
				privateKey,
				to: 'object',
			});
			return encodeDerSignature(r, s);
		};
		return this;
	};
}

const SAFE_TX_TYPED_DATA = {
	domain: {
		chainId: 11155111,
		verifyingContract: '0x6f394dd59f2301340efb711c97b0bb2711915058',
	},
	types: {
		SafeTx: [
			{ name: 'to', type: 'address' },
			{ name: 'value', type: 'uint256' },
			{ name: 'data', type: 'bytes' },
			{ name: 'operation', type: 'uint8' },
			{ name: 'safeTxGas', type: 'uint256' },
			{ name: 'baseGas', type: 'uint256' },
			{ name: 'gasPrice', type: 'uint256' },
			{ name: 'gasToken', type: 'address' },
			{ name: 'refundReceiver', type: 'address' },
			{ name: 'nonce', type: 'uint256' },
		],
	},
	primaryType: 'SafeTx',
	message: {
		to: '0x000000000000000000000000000000000000dEaD',
		value: 1n,
		data: '0x',
		operation: 0,
		safeTxGas: 0n,
		baseGas: 0n,
		gasPrice: 0n,
		gasToken: zeroAddress,
		refundReceiver: zeroAddress,
		nonce: 0n,
	},
} as const;

describe('CoSigner', () => {
	const privateKeys = new Map<string, Hex>();

	beforeEach(() => {
		vi.clearAllMocks();
		privateKeys.clear();
		for (const keyId of ['aws-1', 'aws-2', 'gcp-1']) {
			privateKeys.set(keyId, generatePrivateKey());
		}
		vi.mocked(KmsClient).mockImplementation(
			createFakeKmsClient(privateKeys) as unknown as typeof KmsClient,
		);
		vi.mocked(GcpClient).mockImplementation(
			createFakeKmsClient(privateKeys) as unknown as typeof GcpClient,
		);
	});

	const awsSigner = (keyId: string) =>
		new KmsSigner({ region: 'us-east-1', keyId });
	const gcpSigner = (keyId: string) =>
		new GcpSigner({
			projectId: 'project',
			locationId: 'global',
			keyRingId: 'ring',
			keyId,
			keyVersion: '1',
		});
	const addressOf = (keyId: string) =>
		privateKeyToAccount(privateKeys.get(keyId) as Hex).address.toLowerCase();

	describe('signTypedData', () => {
		test('should produce Safe-compatible packed signatures from mixed AWS and GCP keys', async () => {
			// #given
			const coSigner = new CoSigner({
				signers: [awsSigner('aws-1'), gcpSigner('gcp-1'), awsSigner('aws-2')],
			});
			const safeTxHash = hashTypedData(SAFE_TX_TYPED_DATA);

			// #when
			const { signatures, failures } =
				await coSigner.signTypedData(SAFE_TX_TYPED_DATA);
			const packed = packSafeSignatures(signatures);

			// #then
			expect(failures).toEqual([]);
			expect(size(packed)).toBe(3 * 65);
			const owners = [];
			for (let i = 0; i < 3; i++) {
				const chunk = slice(packed, i * 65, (i + 1) * 65);
				expect([27, 28]).toContain(fromHex(slice(chunk, 64), 'number'));
				const owner = await recoverAddress({
					hash: safeTxHash,
					signature: chunk,
				});
				owners.push(owner.toLowerCase());
			}
			expect(BigInt(owners[0]) < BigInt(owners[1])).toBe(true);
			expect(BigInt(owners[1]) < BigInt(owners[2])).toBe(true);
			expect(new Set(owners)).toEqual(
				new Set([addressOf('aws-1'), addressOf('aws-2'), addressOf('gcp-1')]),
			);
		});

		test('should return successful signatures and failures when threshold is met', async () => {
			// #given
			const coSigner = new CoSigner({
				signers: [
					awsSigner('aws-1'),
					awsSigner(BROKEN_KEY_ID),
					gcpSigner('gcp-1'),
				],
				threshold: 2,
			});

			// #when
			const { signatures, failures } =
				await coSigner.signTypedData(SAFE_TX_TYPED_DATA);

			// #then
			expect(signatures.map(({ address }) => address).sort()).toEqual(
				[addressOf('aws-1'), addressOf('gcp-1')].sort(),
			);
			expect(failures).toHaveLength(1);
			expect(failures[0].signerIndex).toBe(1);
			expect(failures[0].error).toBeInstanceOf(KmsClientError);
		});

		test('should throw CoSignThresholdError with failures when threshold is not met', async () => {
			// #given
			const coSigner = new CoSigner({
				signers: [
					awsSigner('aws-1'),
					awsSigner(BROKEN_KEY_ID),
					gcpSigner('gcp-1'),
				],
			});

			// #when
			const result = coSigner.signTypedData(SAFE_TX_TYPED_DATA);

			// #then
			await expect(result).rejects.toBeInstanceOf(CoSignThresholdError);
			await expect(result).rejects.toMatchObject({
				failures: [{ signerIndex: 1 }],
			});
		});

		test('should reject duplicate signer addresses', async () => {
			// #given
			const coSigner = new CoSigner({
				signers: [awsSigner('aws-1'), awsSigner('aws-1')],
			});

			// #when
			const result = coSigner.signTypedData(SAFE_TX_TYPED_DATA);

			// #then
			await expect(result).rejects.toThrow('Duplicate signer address');
		});
	});

	describe('signMessage', () => {
		test('should return a verifiable EIP-191 signature for every signer', async () => {
			// #given
			const message = 'co-sign me';
			const coSigner = new CoSigner({
				signers: [awsSigner('aws-1'), gcpSigner('gcp-1')],
			});

			// #when
			const { signatures } = await coSigner.signMessage({ message });

			// #then
			expect(signatures).toHaveLength(2);
			for (const { address, signature } of signatures) {
				expect(await verifyMessage({ address, message, signature })).toBe(true);
			}
		});
	});

	describe('getAddresses', () => {
		test('should return addresses in configured order', async () => {
			// #given
			const coSigner = new CoSigner({
				signers: [gcpSigner('gcp-1'), awsSigner('aws-1')],
			});

			// #when
			const addresses = await coSigner.getAddresses();

			// #then
			expect(addresses).toEqual([addressOf('gcp-1'), addressOf('aws-1')]);
		});
	});

	describe('constructor', () => {
		test.each([
			{ name: 'empty signers', signers: 0, threshold: undefined },
			{ name: 'zero threshold', signers: 2, threshold: 0 },
			{ name: 'threshold above signers', signers: 2, threshold: 3 },
			{ name: 'non-integer threshold', signers: 2, threshold: 1.5 },
		])('should throw on $name', ({ signers, threshold }) => {
			// #given
			const members = Array.from({ length: signers }, (_, i) =>
				awsSigner(`aws-${i + 1}`),
			);

			// #when
			const create = () => new CoSigner({ signers: members, threshold });

			// #then
			expect(create).toThrow(KmsSignerError);
		});
	});
});
