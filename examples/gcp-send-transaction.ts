import 'dotenv/config';
import { createWalletClient, http } from 'viem';
import { sepolia } from 'viem/chains';
import { GcpSigner, toGcpKmsAccount } from '../src';

async function main() {
	// Validate environment variables
	const requiredEnvVars = [
		'GCP_PROJECT_ID',
		'GCP_LOCATION_ID',
		'GCP_KEY_RING_ID',
		'GCP_KEY_ID',
		'GCP_KEY_VERSION',
	] as const;
	for (const envVar of requiredEnvVars) {
		if (!process.env[envVar]) {
			throw new Error(`Missing required environment variable: ${envVar}`);
		}
	}

	// Create GCP KMS Signer
	const signer = new GcpSigner({
		projectId: process.env.GCP_PROJECT_ID as string,
		locationId: process.env.GCP_LOCATION_ID as string,
		keyRingId: process.env.GCP_KEY_RING_ID as string,
		keyId: process.env.GCP_KEY_ID as string,
		keyVersion: process.env.GCP_KEY_VERSION as string,
		keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS,
	});

	const account = await toGcpKmsAccount(signer);

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
