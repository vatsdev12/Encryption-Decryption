import { KeyManagementServiceClient } from '@google-cloud/kms';
import crypto from 'crypto';
import createKms from '../utils/createKms';

/**
 * Metadata required for KMS key operations
 */
export interface KeyMetadata {
    locationId: string;
    keyRingId: string;
    keyId: string;
    keyVersion: string;
}

/**
 * Result of DEK encryption operation
 */
interface EncryptDEKResult {
    encryptedDEK: Buffer;
    locationId: string;
    keyRingId: string;
    keyId: string;
    keyVersion: string;
}

/**
 * Parameters required for DEK decryption
 */
interface DecryptDEKParams {
    encryptedDEKData: Buffer;
    keyMetadata: KeyMetadata;
}

/**
 * Service for handling Google Cloud KMS operations
 */
class KMSService {
    private readonly client: KeyManagementServiceClient;
    private readonly projectId: string;
    private readonly locationId: string;
    private readonly keyRingPath: string;

    constructor() {
        this.client = new KeyManagementServiceClient();
        this.projectId = process.env.GOOGLE_CLOUD_PROJECT || '';
        this.locationId = process.env.KMS_LOCATION_ID || 'global';
        this.keyRingPath = this.client.locationPath(this.projectId, this.locationId);

        if (!this.projectId) {
            throw new Error('GOOGLE_CLOUD_PROJECT environment variable is required');
        }
    }

    /**
     * Creates a new key ring and key in Google Cloud KMS
     * @param dek - Data Encryption Key to encrypt
     * @param clientName - Optional name for the KMS key
     * @returns Promise resolving to encryption result with metadata
     */
    private async createKeyRingAndKey(dek: Buffer, clientName?: string): Promise<EncryptDEKResult> {
        const { keyRingId, keyId } = createKms(clientName || crypto.randomBytes(16).toString('hex'));

        try {
            // Create KeyRing
            await this.client.createKeyRing({
                parent: this.keyRingPath,
                keyRingId,
                keyRing: {}
            });

            // Create CryptoKey
            const [key] = await this.client.createCryptoKey({
                parent: this.client.keyRingPath(this.projectId, this.locationId, keyRingId),
                cryptoKeyId: keyId,
                cryptoKey: {
                    purpose: 'ENCRYPT_DECRYPT',
                    versionTemplate: {
                        algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION',
                    },
                }
            });

            const keyVersionName = key.primary?.name;
            if (!keyVersionName) {
                throw new Error('Failed to retrieve primary key version');
            }
            const keyDetailsArray = keyVersionName.split('/');
            // const keyVersionKeyName = keyDetailsArray[keyDetailsArray.length - 2];
            // if (keyVersionKeyName != 'cryptoKeyVersions') {
            //     throw new Error('Failed to retrieve key version key name');
            // }
            const keyVersion = keyDetailsArray[keyDetailsArray.length - 1];
            if (!keyVersion) {
                throw new Error('Failed to retrieve key version');
            }

            if (!key.name) {
                throw new Error('Failed to create crypto key: key name is undefined');
            }

            // Encrypt the DEK
            const [encryptResponse] = await this.client.encrypt({
                name: key.name,
                plaintext: dek
            });

            return {
                encryptedDEK: encryptResponse.ciphertext as Buffer,
                locationId: this.locationId,
                keyRingId,
                keyId,
                keyVersion
            };
        } catch (error) {
            throw new Error(`Failed to create key ring and key: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Encrypts a Data Encryption Key (DEK) using Google Cloud KMS
     * @param dek - Data Encryption Key to encrypt
     * @param clientName - Optional name for the KMS key
     * @returns Promise resolving to encryption result with metadata
     */
    async encryptDEK(dek: Buffer, clientName?: string): Promise<EncryptDEKResult> {
        try {
            return await this.createKeyRingAndKey(dek, clientName);
        } catch (error) {
            throw new Error(`Failed to encrypt DEK: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Decrypts a Data Encryption Key (DEK) using Google Cloud KMS
     * @param params - Parameters containing encrypted DEK and key metadata
     * @returns Promise resolving to decrypted DEK
     */
    async decryptDEK({ encryptedDEKData, keyMetadata }: DecryptDEKParams): Promise<Buffer> {
        try {
            const keyName = this.client.cryptoKeyVersionPath(
                this.projectId,
                keyMetadata.locationId,
                keyMetadata.keyRingId,
                keyMetadata.keyId,
                keyMetadata.keyVersion
            );

            const [decryptResponse] = await this.client.decrypt({
                name: keyName,
                ciphertext: encryptedDEKData
            });

            const dek = decryptResponse.plaintext as Buffer;

            if (dek.length !== 32) {
                throw new Error(`Invalid DEK length: ${dek.length} bytes. Expected 32 bytes for AES-256-GCM`);
            }

            return dek;
        } catch (error) {
            throw new Error(`Failed to decrypt DEK: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
}

export default new KMSService(); 