import type { TransactionSerializable } from 'viem';
import {
	fromHex,
	getAddress,
	parseTransaction,
	recoverTransactionAddress,
} from 'viem';
import {
	generatePrivateKey,
	privateKeyToAccount,
	sign as viemSign,
} from 'viem/accounts';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import { GcpClient } from './gcp/client.js';
import { GcpSigner } from './gcp/signer.js';
import { KmsClient } from './kms/client.js';
import { KmsSigner } from './kms/signer.js';

vi.mock('./kms/client.js', () => ({ KmsClient: vi.fn() }));
vi.mock('./gcp/client.js', () => ({ GcpClient: vi.fn() }));

// ASN.1 DER encoder for a secp256k1 ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }).
// Mirrors what AWS/GCP KMS returns so tests can feed real viem-produced signatures
// through the production DER parser path.
function encodeDerInteger(value: Uint8Array): Uint8Array {
	let start = 0;
	while (start < value.length - 1 && value[start] === 0) start++;
	let body = value.slice(start);
	if ((body[0] & 0x80) !== 0) {
		const padded = new Uint8Array(body.length + 1);
		padded[0] = 0x00;
		padded.set(body, 1);
		body = padded;
	}
	const header = new Uint8Array([0x02, body.length]);
	const out = new Uint8Array(header.length + body.length);
	out.set(header, 0);
	out.set(body, header.length);
	return out;
}

function bigintToBytes32(value: bigint): Uint8Array {
	const hex = value.toString(16).padStart(64, '0');
	const bytes = new Uint8Array(32);
	for (let i = 0; i < 32; i++) {
		bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return bytes;
}

function encodeDerSignature(r: bigint, s: bigint): Uint8Array {
	const rDer = encodeDerInteger(bigintToBytes32(r));
	const sDer = encodeDerInteger(bigintToBytes32(s));
	const content = new Uint8Array(rDer.length + sDer.length);
	content.set(rDer, 0);
	content.set(sDer, rDer.length);
	const out = new Uint8Array(content.length + 2);
	out[0] = 0x30;
	out[1] = content.length;
	out.set(content, 2);
	return out;
}

function setupRealCryptoMock(
	clientMock: ReturnType<typeof vi.fn>,
	privateKey: `0x${string}`,
) {
	const account = privateKeyToAccount(privateKey);
	const publicKeyBytes = fromHex(account.publicKey, 'bytes');

	clientMock.mockImplementation(function (this: {
		getPublicKey: () => Promise<Uint8Array>;
		sign: (hash: Uint8Array) => Promise<Uint8Array>;
	}) {
		this.getPublicKey = async () => publicKeyBytes;
		this.sign = async (hash: Uint8Array) => {
			const hashHex = `0x${Array.from(hash)
				.map((b) => b.toString(16).padStart(2, '0'))
				.join('')}` as `0x${string}`;
			const sig = await viemSign({
				hash: hashHex,
				privateKey,
				to: 'object',
			});
			const r = BigInt(sig.r);
			const s = BigInt(sig.s);
			return encodeDerSignature(r, s);
		};
		return this;
	});

	return account;
}

describe('signTransaction yParity round-trip (issue #98)', () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	describe('KmsSigner', () => {
		test('EIP-1559 typed transaction recovers to signer address', async () => {
			// #given
			const privateKey = generatePrivateKey();
			const account = setupRealCryptoMock(vi.mocked(KmsClient), privateKey);
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key',
			});
			const transaction: TransactionSerializable = {
				type: 'eip1559',
				chainId: 11155111,
				nonce: 18,
				maxFeePerGas: 12_090_378n,
				maxPriorityFeePerGas: 1_000_000n,
				gas: 59_850n,
				to: getAddress('0x6f394dd59f2301340efb711c97b0bb2711915058'),
				value: 0n,
				data: '0x',
			};

			// #when
			const serialized = await signer.signTransaction(transaction);

			// #then
			const recovered = await recoverTransactionAddress({
				serializedTransaction: serialized,
			});
			expect(recovered).toBe(account.address);
			const parsed = parseTransaction(serialized);
			expect(parsed.type).toBe('eip1559');
			expect(parsed.yParity === 0 || parsed.yParity === 1).toBe(true);
		});

		test('EIP-2930 typed transaction recovers to signer address', async () => {
			// #given
			const privateKey = generatePrivateKey();
			const account = setupRealCryptoMock(vi.mocked(KmsClient), privateKey);
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key',
			});
			const transaction: TransactionSerializable = {
				type: 'eip2930',
				chainId: 1,
				nonce: 0,
				gasPrice: 20_000_000_000n,
				gas: 21_000n,
				to: getAddress('0x6f394dd59f2301340efb711c97b0bb2711915058'),
				value: 0n,
				accessList: [],
			};

			// #when
			const serialized = await signer.signTransaction(transaction);

			// #then
			const recovered = await recoverTransactionAddress({
				serializedTransaction: serialized,
			});
			expect(recovered).toBe(account.address);
			const parsed = parseTransaction(serialized);
			expect(parsed.type).toBe('eip2930');
		});

		test('legacy EIP-155 transaction recovers to signer address (regression)', async () => {
			// #given
			const privateKey = generatePrivateKey();
			const account = setupRealCryptoMock(vi.mocked(KmsClient), privateKey);
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key',
			});
			const transaction: TransactionSerializable = {
				type: 'legacy',
				chainId: 1,
				nonce: 0,
				gasPrice: 20_000_000_000n,
				gas: 21_000n,
				to: getAddress('0x6f394dd59f2301340efb711c97b0bb2711915058'),
				value: 1n,
			};

			// #when
			const serialized = await signer.signTransaction(transaction);

			// #then
			const recovered = await recoverTransactionAddress({
				serializedTransaction: serialized,
			});
			expect(recovered).toBe(account.address);
			const parsed = parseTransaction(serialized);
			expect(parsed.type).toBe('legacy');
			// EIP-155: v = chainId * 2 + 35 + recoveryId, so v ∈ {37, 38} for chainId 1
			expect(parsed.v === 37n || parsed.v === 38n).toBe(true);
		});

		test('legacy transaction without chainId recovers to signer address (pre-EIP-155)', async () => {
			// #given
			const privateKey = generatePrivateKey();
			const account = setupRealCryptoMock(vi.mocked(KmsClient), privateKey);
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key',
			});
			const transaction: TransactionSerializable = {
				type: 'legacy',
				nonce: 0,
				gasPrice: 20_000_000_000n,
				gas: 21_000n,
				to: getAddress('0x6f394dd59f2301340efb711c97b0bb2711915058'),
				value: 1n,
			};

			// #when
			const serialized = await signer.signTransaction(transaction);

			// #then
			const recovered = await recoverTransactionAddress({
				serializedTransaction: serialized,
			});
			expect(recovered).toBe(account.address);
			const parsed = parseTransaction(serialized);
			expect(parsed.v === 27n || parsed.v === 28n).toBe(true);
		});
	});

	describe('GcpSigner', () => {
		test('EIP-1559 typed transaction recovers to signer address', async () => {
			// #given
			const privateKey = generatePrivateKey();
			const account = setupRealCryptoMock(vi.mocked(GcpClient), privateKey);
			const signer = new GcpSigner({
				projectId: 'test-project',
				locationId: 'global',
				keyRingId: 'test-keyring',
				keyId: 'test-key',
				keyVersion: '1',
			});
			const transaction: TransactionSerializable = {
				type: 'eip1559',
				chainId: 11155111,
				nonce: 18,
				maxFeePerGas: 12_090_378n,
				maxPriorityFeePerGas: 1_000_000n,
				gas: 59_850n,
				to: getAddress('0x6f394dd59f2301340efb711c97b0bb2711915058'),
				value: 0n,
				data: '0x',
			};

			// #when
			const serialized = await signer.signTransaction(transaction);

			// #then
			const recovered = await recoverTransactionAddress({
				serializedTransaction: serialized,
			});
			expect(recovered).toBe(account.address);
			const parsed = parseTransaction(serialized);
			expect(parsed.type).toBe('eip1559');
			expect(parsed.yParity === 0 || parsed.yParity === 1).toBe(true);
		});

		test('EIP-2930 typed transaction recovers to signer address', async () => {
			// #given
			const privateKey = generatePrivateKey();
			const account = setupRealCryptoMock(vi.mocked(GcpClient), privateKey);
			const signer = new GcpSigner({
				projectId: 'test-project',
				locationId: 'global',
				keyRingId: 'test-keyring',
				keyId: 'test-key',
				keyVersion: '1',
			});
			const transaction: TransactionSerializable = {
				type: 'eip2930',
				chainId: 1,
				nonce: 0,
				gasPrice: 20_000_000_000n,
				gas: 21_000n,
				to: getAddress('0x6f394dd59f2301340efb711c97b0bb2711915058'),
				value: 0n,
				accessList: [],
			};

			// #when
			const serialized = await signer.signTransaction(transaction);

			// #then
			const recovered = await recoverTransactionAddress({
				serializedTransaction: serialized,
			});
			expect(recovered).toBe(account.address);
			const parsed = parseTransaction(serialized);
			expect(parsed.type).toBe('eip2930');
		});

		test('legacy EIP-155 transaction recovers to signer address (regression)', async () => {
			// #given
			const privateKey = generatePrivateKey();
			const account = setupRealCryptoMock(vi.mocked(GcpClient), privateKey);
			const signer = new GcpSigner({
				projectId: 'test-project',
				locationId: 'global',
				keyRingId: 'test-keyring',
				keyId: 'test-key',
				keyVersion: '1',
			});
			const transaction: TransactionSerializable = {
				type: 'legacy',
				chainId: 1,
				nonce: 0,
				gasPrice: 20_000_000_000n,
				gas: 21_000n,
				to: getAddress('0x6f394dd59f2301340efb711c97b0bb2711915058'),
				value: 1n,
			};

			// #when
			const serialized = await signer.signTransaction(transaction);

			// #then
			const recovered = await recoverTransactionAddress({
				serializedTransaction: serialized,
			});
			expect(recovered).toBe(account.address);
			const parsed = parseTransaction(serialized);
			expect(parsed.type).toBe('legacy');
			expect(parsed.v === 37n || parsed.v === 38n).toBe(true);
		});
	});
});

// Issue #102 reported a ~50% failure rate for EIP-1559 transactions: whenever
// the recovery id happened to be 0 the previous code fed an EIP-155 v
// (e.g. v=37 on mainnet) into viem's typed serializer, which silently fell
// back to `yParity = 1` and produced a signature that recovered to the wrong
// address. We iterate over many random keys so both recoveryId values are
// statistically guaranteed to be exercised in a single test run; without the
// fix shipped in #111 the recoveryId=0 iterations would fail.
const STATISTICAL_ITERATIONS = 25;

describe('signTransaction yParity round-trip (issue #102 regression)', () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	test('KmsSigner: EIP-1559 round-trips across many keys, covering both yParity 0 and 1', async () => {
		// #given
		const observedYParities = new Set<number>();

		for (let i = 0; i < STATISTICAL_ITERATIONS; i++) {
			const privateKey = generatePrivateKey();
			const account = setupRealCryptoMock(vi.mocked(KmsClient), privateKey);
			const signer = new KmsSigner({
				region: 'us-east-1',
				keyId: 'test-key',
			});
			const transaction: TransactionSerializable = {
				type: 'eip1559',
				chainId: 1,
				nonce: i,
				maxFeePerGas: 12_090_378n,
				maxPriorityFeePerGas: 1_000_000n,
				gas: 59_850n,
				to: getAddress('0x6f394dd59f2301340efb711c97b0bb2711915058'),
				value: 0n,
				data: '0x',
			};

			// #when
			const serialized = await signer.signTransaction(transaction);

			// #then
			const recovered = await recoverTransactionAddress({
				serializedTransaction: serialized,
			});
			expect(recovered).toBe(account.address);

			const parsed = parseTransaction(serialized);
			expect(parsed.type).toBe('eip1559');
			expect(parsed.yParity === 0 || parsed.yParity === 1).toBe(true);
			observedYParities.add(parsed.yParity as number);
		}

		// Statistical guarantee: with 25 random keys the probability of seeing
		// only one yParity value is 2 * 2^-25 ≈ 6e-8.
		expect(observedYParities.has(0)).toBe(true);
		expect(observedYParities.has(1)).toBe(true);
	});

	test('GcpSigner: EIP-1559 round-trips across many keys, covering both yParity 0 and 1', async () => {
		// #given
		const observedYParities = new Set<number>();

		for (let i = 0; i < STATISTICAL_ITERATIONS; i++) {
			const privateKey = generatePrivateKey();
			const account = setupRealCryptoMock(vi.mocked(GcpClient), privateKey);
			const signer = new GcpSigner({
				projectId: 'test-project',
				locationId: 'global',
				keyRingId: 'test-keyring',
				keyId: 'test-key',
				keyVersion: '1',
			});
			const transaction: TransactionSerializable = {
				type: 'eip1559',
				chainId: 1,
				nonce: i,
				maxFeePerGas: 12_090_378n,
				maxPriorityFeePerGas: 1_000_000n,
				gas: 59_850n,
				to: getAddress('0x6f394dd59f2301340efb711c97b0bb2711915058'),
				value: 0n,
				data: '0x',
			};

			// #when
			const serialized = await signer.signTransaction(transaction);

			// #then
			const recovered = await recoverTransactionAddress({
				serializedTransaction: serialized,
			});
			expect(recovered).toBe(account.address);

			const parsed = parseTransaction(serialized);
			expect(parsed.type).toBe('eip1559');
			expect(parsed.yParity === 0 || parsed.yParity === 1).toBe(true);
			observedYParities.add(parsed.yParity as number);
		}

		// Statistical guarantee: same probability as the KmsSigner case.
		expect(observedYParities.has(0)).toBe(true);
		expect(observedYParities.has(1)).toBe(true);
	});
});
