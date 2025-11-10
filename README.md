# kms-signer-evm

A TypeScript library that integrates AWS KMS (Key Management Service) with [viem](https://viem.sh) to create secure Ethereum signers. This allows you to sign Ethereum transactions and messages using keys stored in AWS KMS, providing enterprise-grade security for your Ethereum operations.

## Features

- **AWS KMS Integration**: Sign Ethereum transactions using keys securely stored in AWS KMS
- **Full EIP Compliance**: Supports EIP-191 (personal messages), EIP-712 (typed data), EIP-155 (replay protection), EIP-2 (signature normalization)
- **Type-Safe**: Built with TypeScript in strict mode with comprehensive type definitions
- **viem Compatible**: Seamlessly integrates with viem's Account system via `toAccount`
- **DER Signature Parsing**: Automatically converts AWS KMS DER-encoded signatures to Ethereum format
- **Comprehensive Error Handling**: Custom error classes for better debugging
- **Well-Tested**: 51 tests covering all functionality with 100% type safety

## Installation

```bash
pnpm add kms-signer-evm
```

Or with npm:

```bash
npm install kms-signer-evm
```

Or with yarn:

```bash
yarn add kms-signer-evm
```

## Prerequisites

### AWS KMS Key Setup

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

### Environment Variables

Create a `.env` file in your project root:

```env
AWS_REGION=us-east-1
KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012

# Optional: If not using IAM roles or default credentials
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
```

## Quick Start

### Signing a Message

```typescript
import 'dotenv/config'
import { KmsSigner, toKmsAccount } from 'kms-signer-evm'

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

### Sending a Transaction

```typescript
import 'dotenv/config'
import { createWalletClient, http } from 'viem'
import { sepolia } from 'viem/chains'
import { KmsSigner, toKmsAccount } from 'kms-signer-evm'

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
2. **Environment Variables**: Never commit `.env` files with credentials
3. **Key Policies**: Restrict KMS key usage to specific AWS principals
4. **Audit Logging**: Enable AWS CloudTrail to monitor KMS key usage
5. **Network Security**: Use VPC endpoints for KMS in production environments

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
- Inspired by the need for secure key management in Ethereum applications
