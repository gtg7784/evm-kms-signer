import 'dotenv/config';
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

	// GCP KMS configuration
	const signer = new GcpSigner({
		projectId: process.env.GCP_PROJECT_ID as string,
		locationId: process.env.GCP_LOCATION_ID as string,
		keyRingId: process.env.GCP_KEY_RING_ID as string,
		keyId: process.env.GCP_KEY_ID as string,
		keyVersion: process.env.GCP_KEY_VERSION as string,
		keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS,
	});

	// Convert to viem Account
	const account = await toGcpKmsAccount(signer);
	console.log('Account address:', account.address);

	// Sign message
	const message = 'Hello, GCP KMS!';
	const signature = await account.signMessage({ message });

	console.log('Message:', message);
	console.log('Signature:', signature);
}

main().catch(console.error);
