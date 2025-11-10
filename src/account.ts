import { toAccount } from 'viem/accounts'
import type { LocalAccount } from 'viem'
import { KmsSigner } from './kms/signer'

/**
 * Create a viem Account from KmsSigner.
 *
 * Wraps KmsSigner methods to match viem's Account interface,
 * enabling use with viem clients (walletClient, etc.)
 *
 * @param signer - KmsSigner instance
 * @returns viem Account with KMS signing capabilities
 *
 * @example
 * ```typescript
 * const signer = new KmsSigner({ region: 'us-east-1', keyId: 'key-id' })
 * const account = await toKmsAccount(signer)
 *
 * const client = createWalletClient({
 *   account,
 *   chain: mainnet,
 *   transport: http()
 * })
 * ```
 */
export async function toKmsAccount(signer: KmsSigner): Promise<LocalAccount> {
  const address = await signer.getAddress()

  return toAccount({
    address,
    signMessage: async ({ message }) => {
      // Convert SignableMessage to string for KmsSigner
      const messageStr = typeof message === 'string' ? message : message.raw.toString()
      return signer.signMessage({ message: messageStr })
    },
    signTransaction: async (transaction, options) => signer.signTransaction(transaction, options),
    signTypedData: async (typedData) => signer.signTypedData(typedData)
  })
}
