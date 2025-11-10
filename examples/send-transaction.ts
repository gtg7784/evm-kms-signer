import 'dotenv/config';
import { createWalletClient, http } from 'viem';
import { sepolia } from 'viem/chains';
import { KmsSigner, toKmsAccount } from '../src';

async function main() {
	// Validate environment variables
	const requiredEnvVars = ['AWS_REGION', 'KMS_KEY_ID'] as const;
	for (const envVar of requiredEnvVars) {
		if (!process.env[envVar]) {
			throw new Error(`Missing required environment variable: ${envVar}`);
		}
	}

	// Create KMS Signer
	const signer = new KmsSigner({
		region: process.env.AWS_REGION as string,
		keyId: process.env.KMS_KEY_ID as string,
	});

	const account = await toKmsAccount(signer);

	// Create Wallet Client
	const client = createWalletClient({
		account,
		chain: sepolia,
		transport: http(),
	});

	// Send transaction
	const hash = await client.sendTransaction({
		to: '0xa5D3241A1591061F2a4bB69CA0215F66520E67cf',
		value: 1000000000000000n, // 0.001 ETH
	});

	console.log('Transaction hash:', hash);
}

main().catch(console.error);
