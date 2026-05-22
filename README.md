# evm-kms-signer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue.svg)](https://www.typescriptlang.org/)
[![Node](https://img.shields.io/badge/Node-%3E%3D22.13.0-green.svg)](https://nodejs.org/)
[![npm](https://img.shields.io/npm/v/evm-kms-signer.svg)](https://www.npmjs.com/package/evm-kms-signer)
[![AWS KMS](https://img.shields.io/badge/AWS-KMS-orange.svg)](https://aws.amazon.com/kms/)
[![GCP KMS](https://img.shields.io/badge/GCP-KMS-blue.svg)](https://cloud.google.com/kms)

A TypeScript library that integrates AWS/GCP KMS (Key Management Service) with [viem](https://viem.sh) to create secure Ethereum signers. This allows you to sign Ethereum transactions and messages using keys stored in AWS or GCP KMS, providing enterprise-grade security for your Ethereum operations.

## Features

- **AWS KMS Integration**: Sign Ethereum transactions using keys securely stored in AWS KMS
- **GCP KMS Support**: Also supports Google Cloud Platform KMS for multi-cloud deployments
- **Full EIP Compliance**: Supports EIP-191 (personal messages), EIP-712 (typed data), EIP-155 (replay protection), EIP-2 (signature normalization)
- **Type-Safe**: Built with TypeScript in strict mode with comprehensive type definitions
- **viem Compatible**: Seamlessly integrates with viem's Account system via `toAccount`
- **DER Signature Parsing**: Automatically converts AWS/GCP KMS DER-encoded signatures to Ethereum format
- **Comprehensive Error Handling**: Custom error classes for better debugging
- **Well-Tested**: 169 tests covering all functionality with 100% type safety

## Installation

```bash
pnpm add evm-kms-signer
```

Or with npm:

```bash
npm install evm-kms-signer
```

Or with yarn:

```bash
yarn add evm-kms-signer
```

## Usage

### AWS KMS

#### Prerequisites

1. **Create an ECC Key in AWS KMS**:
   - Go to AWS KMS Console
   - Click "Create key"
   - Choose "Asymmetric" key type
   - Select "Sign and verify" key usage
   - Choose **ECC_SECG_P256K1** as the key spec (this is secp256k1, Ethereum's curve)
   - Complete the key creation process

2. **Grant Permissions**:
   Ensure your AWS credentials have the following permissions:
   - `kms:GetPublicKey`
   - `kms:Sign`

3. **Note Your Key ID**:
   Copy the Key ARN or Key ID for use in your application.

#### Environment Variables

Create a `.env` file in your project root:

```env
AWS_REGION=us-east-1
KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012

# Optional: If not using IAM roles or default credentials
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
```

#### Basic Usage

```typescript
import 'dotenv/config'
import { KmsSigner, toKmsAccount } from 'evm-kms-signer'

async function main() {
  // Initialize the KMS signer
  const signer = new KmsSigner({
    region: process.env.AWS_REGION!,
    keyId: process.env.KMS_KEY_ID!,
  })

  // Convert to viem account
  const account = await toKmsAccount(signer)

  console.log('Account address:', account.address)

  // Sign a message
  const message = 'Hello from AWS KMS!'
  const signature = await account.signMessage({ message })

  console.log('Signature:', signature)
}

main().catch(console.error)
```

#### Use with viem

```typescript
import 'dotenv/config'
import { createWalletClient, http } from 'viem'
import { sepolia } from 'viem/chains'
import { KmsSigner, toKmsAccount } from 'evm-kms-signer'

async function main() {
  // Initialize the KMS signer
  const signer = new KmsSigner({
    region: process.env.AWS_REGION!,
    keyId: process.env.KMS_KEY_ID!,
  })

  // Convert to viem account
  const account = await toKmsAccount(signer)

  // Create a wallet client
  const client = createWalletClient({
    account,
    chain: sepolia,
    transport: http()
  })

  // Send a transaction
  const hash = await client.sendTransaction({
    to: '0xa5D3241A1591061F2a4bB69CA0215F66520E67cf',
    value: 1000000000000000n, // 0.001 ETH
  })

  console.log('Transaction hash:', hash)
}

main().catch(console.error)
```

#### EKS Pod Identity

This library fully supports [EKS Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html) for secure, credential-free authentication in Kubernetes environments. When running in EKS with Pod Identity configured, no explicit credentials are needed.

##### How It Works

The AWS SDK for JavaScript v3 automatically detects and uses the default credential provider chain:

1. **Environment variables** (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. **EKS Pod Identity** (`AWS_CONTAINER_CREDENTIALS_FULL_URI`)
3. **ECS container credentials**
4. **EC2 instance metadata (IMDS)**
5. **Shared credentials file** (`~/.aws/credentials`)

When credentials are not explicitly provided, the SDK automatically discovers available credentials in the above order.

##### Setup Steps

1. **Install the EKS Pod Identity Agent** addon in your cluster:
   ```bash
   aws eks create-addon \
     --cluster-name <cluster-name> \
     --addon-name eks-pod-identity-agent
   ```

2. **Create an IAM role** with the required KMS permissions:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "kms:GetPublicKey",
           "kms:Sign"
         ],
         "Resource": "arn:aws:kms:<region>:<account-id>:key/<key-id>"
       }
     ]
   }
   ```

3. **Create a Pod Identity association**:
   ```bash
   aws eks create-pod-identity-association \
     --cluster-name <cluster-name> \
     --namespace <namespace> \
     --service-account <service-account-name> \
     --role-arn arn:aws:iam::<account-id>:role/<role-name>
   ```

4. **Use the library without explicit credentials**:
   ```typescript
   import { KmsSigner, toKmsAccount } from 'evm-kms-signer'

   // No credentials needed - EKS Pod Identity handles authentication
   const signer = new KmsSigner({
     region: process.env.AWS_REGION!,
     keyId: process.env.KMS_KEY_ID!,
     // credentials are automatically discovered via Pod Identity
   })

   const account = await toKmsAccount(signer)
   ```

##### Verification

To verify Pod Identity is working, check that these environment variables are set in your pod:
```bash
kubectl exec -it <pod-name> -- env | grep AWS_CONTAINER
# Should show:
# AWS_CONTAINER_CREDENTIALS_FULL_URI=http://169.254.170.23/v1/credentials
# AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token
```

### GCP KMS

#### Prerequisites

1. **Create a KMS key ring and crypto key in GCP Console**:
   - Go to Google Cloud Console → Security → Key Management
   - Create a new key ring in your desired location
   - Create a crypto key with purpose "Asymmetric sign"
   - Choose **Elliptic Curve P-256 - SHA256 Digest** algorithm (secp256k1 for Ethereum)

2. **Grant Permissions**:
   Grant `roles/cloudkms.cryptoKeySignerVerifier` permission to your service account:
   ```bash
   gcloud kms keys add-iam-policy-binding KEY_ID \
     --location=LOCATION \
     --keyring=KEYRING_ID \
     --member=serviceAccount:SERVICE_ACCOUNT_EMAIL \
     --role=roles/cloudkms.cryptoKeySignerVerifier
   ```

3. **Set up authentication**:
   - Set `GOOGLE_APPLICATION_CREDENTIALS` environment variable pointing to your service account key file, or
   - Pass `keyFilename` in config

#### Basic Usage

```typescript
import { GcpSigner } from 'evm-kms-signer';

const signer = new GcpSigner({
  projectId: 'your-project-id',
  locationId: 'global',
  keyRingId: 'your-keyring-id',
  keyId: 'your-key-id',
  keyVersion: '1',
  keyFilename: '/path/to/service-account-key.json', // optional
});

const address = await signer.getAddress();
const signature = await signer.signMessage({ message: 'Hello!' });
```

#### Use with viem

```typescript
import { createWalletClient, http } from 'viem';
import { mainnet } from 'viem/chains';
import { toGcpKmsAccount } from 'evm-kms-signer';

const account = await toGcpKmsAccount(signer);
const client = createWalletClient({
  account,
  chain: mainnet,
  transport: http(),
});
```

## API Documentation

### `KmsSigner`

The main class for signing operations using AWS KMS.

#### Constructor

```typescript
new KmsSigner(config: KmsConfig)
```

**Parameters:**
- `config.region`: AWS region where your KMS key is located
- `config.keyId`: AWS KMS key ID or ARN
- `config.credentials` (optional): AWS credentials object with `accessKeyId` and `secretAccessKey`

#### Methods

##### `getAddress(): Promise<Address>`

Returns the Ethereum address derived from the KMS public key.

```typescript
const address = await signer.getAddress()
```

##### `getPublicKey(): Promise<Uint8Array>`

Returns the uncompressed public key (65 bytes) from AWS KMS.

```typescript
const publicKey = await signer.getPublicKey()
```

##### `signMessage({ message }): Promise<Hex>`

Signs a personal message (EIP-191).

```typescript
const signature = await signer.signMessage({ message: 'Hello World' })
```

##### `signTransaction(transaction, options?): Promise<Hex>`

Signs an Ethereum transaction with EIP-155 replay protection.

```typescript
const signedTx = await signer.signTransaction({
  to: '0x...',
  value: 1000000000000000n,
  chainId: 11155111,
  nonce: 0,
  maxFeePerGas: 20000000000n,
  maxPriorityFeePerGas: 1000000000n,
})
```

##### `signTypedData(typedData): Promise<Hex>`

Signs structured data (EIP-712).

```typescript
const signature = await signer.signTypedData({
  domain: {
    name: 'Ether Mail',
    version: '1',
    chainId: 1,
    verifyingContract: '0x...'
  },
  types: {
    Person: [
      { name: 'name', type: 'string' },
      { name: 'wallet', type: 'address' }
    ]
  },
  primaryType: 'Person',
  message: {
    name: 'Bob',
    wallet: '0x...'
  }
})
```

### `toKmsAccount(signer: KmsSigner): Promise<LocalAccount>`

Converts a `KmsSigner` instance to a viem `LocalAccount` that can be used with viem's wallet clients.

```typescript
const account = await toKmsAccount(signer)

const client = createWalletClient({
  account,
  chain: mainnet,
  transport: http()
})
```

### Error Classes

The library provides custom error classes for better error handling:

- `KmsSignerError`: Base error class
- `DerParsingError`: Thrown when DER signature parsing fails
- `KmsClientError`: Thrown when AWS KMS operations fail
- `SignatureNormalizationError`: Thrown when signature normalization fails
- `RecoveryIdCalculationError`: Thrown when recovery ID calculation fails

## Security Considerations

### Key Management

- **Private keys never leave AWS KMS**: All signing operations happen within AWS KMS
- **IAM Permissions**: Use least-privilege IAM policies for KMS access
- **Key Rotation**: Consider AWS KMS key rotation policies for your use case

### Signature Security

- **EIP-2 Compliance**: All signatures are normalized to prevent malleability attacks
- **Replay Protection**: Transaction signatures include EIP-155 chainId by default
- **Recovery ID**: Automatically calculated and verified for all signatures

### Best Practices

1. **Use IAM Roles**: Prefer IAM roles over hardcoded credentials in production
2. **Use EKS Pod Identity**: For Kubernetes deployments, use [EKS Pod Identity](#eks-pod-identity) for secure, automatic credential management
3. **Environment Variables**: Never commit `.env` files with credentials
4. **Key Policies**: Restrict KMS key usage to specific AWS principals
5. **Audit Logging**: Enable AWS CloudTrail to monitor KMS key usage
6. **Network Security**: Use VPC endpoints for KMS in production environments

## Development

### Running Tests

```bash
pnpm test:run
```

### Type Checking

```bash
pnpm type-check
```

### Building

```bash
pnpm build
```

### Running Examples

```bash
# Sign a message
pnpm example:sign

# Send a transaction
pnpm example:tx
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- Built with [viem](https://viem.sh) - Modern TypeScript Ethereum library
- Uses [AWS SDK for JavaScript v3](https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/)
- Uses [Google Cloud KMS Client Library](https://cloud.google.com/nodejs/docs/reference/kms/latest)
- Inspired by the need for secure key management in Ethereum applications
