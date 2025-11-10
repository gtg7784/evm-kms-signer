import 'dotenv/config';
import { KmsSigner, toKmsAccount } from '../src';

async function main() {
	// Validate environment variables
	const requiredEnvVars = ['AWS_REGION', 'KMS_KEY_ID'] as const;
	for (const envVar of requiredEnvVars) {
		if (!process.env[envVar]) {
			throw new Error(`Missing required environment variable: ${envVar}`);
		}
	}

	// KMS configuration
	const signer = new KmsSigner({
		region: process.env.AWS_REGION as string,
		keyId: process.env.KMS_KEY_ID as string,
	});

	// Convert to viem Account
	const account = await toKmsAccount(signer);
	console.log('Account address:', account.address);

	// Sign message
	const message = 'Hello from AWS KMS!';
	const signature = await account.signMessage({ message });

	console.log('Message:', message);
	console.log('Signature:', signature);
}

main().catch(console.error);
