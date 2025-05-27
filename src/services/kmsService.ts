import { KeyManagementServiceClient } from '@google-cloud/kms';
import crypto from 'crypto';
import createKms from '../utils/createKms';
import {
    ConfigurationError,
    EncryptionError,
    ValidationError,
    ErrorCodes
} from '../types/errors';
import dotenv from 'dotenv';

dotenv.config();

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
    kmsPath: string;
}

/**
 * Parameters required for DEK decryption
 */
interface DecryptDEKParams {
    encryptedDEKData: Buffer;
    kmsPath: string;
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
        try {
            this.client = new KeyManagementServiceClient();
            this.projectId = process.env.GOOGLE_CLOUD_PROJECT || '';
            this.locationId = process.env.KMS_LOCATION_ID || 'global';
            this.keyRingPath = this.client.locationPath(this.projectId, this.locationId);

            if (!this.projectId) {
                throw new ConfigurationError(
                    'GOOGLE_CLOUD_PROJECT environment variable is required',
                    ErrorCodes.CONFIGURATION.MISSING_ENV_VAR
                );
            }
        } catch (error) {
            if (error instanceof ConfigurationError) {
                throw error;
            }
            throw new ConfigurationError(
                `Failed to initialize KMS service: ${error instanceof Error ? error.message : 'Unknown error'}`,
                ErrorCodes.CONFIGURATION.INITIALIZATION_ERROR
            );
        }
    }

    /**
     * Creates a new key ring and key in Google Cloud KMS
     * @param dek - Data Encryption Key to encrypt
     * @param clientName - Optional name for the KMS key
     * @returns Promise resolving to encryption result with metadata
     * @throws {EncryptionError} When key creation or encryption fails
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
                throw new EncryptionError(
                    'Failed to retrieve primary key version',
                    ErrorCodes.ENCRYPTION.KEY_VERSION_ERROR
                );
            }

            const keyDetailsArray = keyVersionName.split('/');
            const keyVersion = keyDetailsArray[keyDetailsArray.length - 1];
            if (!keyVersion) {
                throw new EncryptionError(
                    'Failed to retrieve key version',
                    ErrorCodes.ENCRYPTION.KEY_VERSION_ERROR
                );
            }

            if (!key.name) {
                throw new EncryptionError(
                    'Failed to create crypto key: key name is undefined',
                    ErrorCodes.ENCRYPTION.KEY_CREATION_ERROR
                );
            }

            // Encrypt the DEK
            const [encryptResponse] = await this.client.encrypt({
                name: key.name,
                plaintext: dek
            });

            return {
                encryptedDEK: encryptResponse.ciphertext as Buffer,
                kmsPath: keyVersionName
            };
        } catch (error) {
            if (error instanceof EncryptionError) {
                throw error;
            }
            throw new EncryptionError(
                `Failed to create key ring and key: ${error instanceof Error ? error.message : 'Unknown error'}`,
                ErrorCodes.ENCRYPTION.KEY_CREATION_ERROR
            );
        }
    }

    /**
     * Encrypts a Data Encryption Key (DEK) using Google Cloud KMS
     * @param dek - Data Encryption Key to encrypt
     * @param clientName - Optional name for the KMS key
     * @returns Promise resolving to encryption result with metadata
     * @throws {EncryptionError} When encryption fails
     */
    async encryptDEK(dek: Buffer, clientName?: string): Promise<EncryptDEKResult> {
        try {
            if (!dek || dek.length !== 32) {
                throw new ValidationError(
                    'Invalid DEK: must be 32 bytes for AES-256-GCM',
                    ErrorCodes.VALIDATION.INVALID_DEK
                );
            }
            return await this.createKeyRingAndKey(dek, clientName);
        } catch (error) {
            if (error instanceof ValidationError || error instanceof EncryptionError) {
                throw error;
            }
            throw new EncryptionError(
                `Failed to encrypt DEK: ${error instanceof Error ? error.message : 'Unknown error'}`,
                ErrorCodes.ENCRYPTION.DEK_ENCRYPTION_ERROR
            );
        }
    }

    /**
     * Decrypts a Data Encryption Key (DEK) using Google Cloud KMS
     * @param params - Parameters containing encrypted DEK and key metadata
     * @returns Promise resolving to decrypted DEK
     * @throws {ValidationError} When input parameters are invalid
     * @throws {EncryptionError} When decryption fails
     */
    async decryptDEK({ encryptedDEKData, kmsPath }: DecryptDEKParams): Promise<Buffer> {
        try {
            if (!encryptedDEKData) {
                throw new ValidationError(
                    'Encrypted DEK data is required',
                    ErrorCodes.VALIDATION.MISSING_REQUIRED_FIELD
                );
            }

            if (!kmsPath) {
                throw new ValidationError(
                    'Missing required key metadata',
                    ErrorCodes.VALIDATION.MISSING_REQUIRED_FIELD
                );
            }
            const keyMetadata = kmsPath.split('/').slice(0,8).join('/');


            const [decryptResponse] = await this.client.decrypt({
                name: keyMetadata,
                ciphertext: encryptedDEKData
            });

            const dek = decryptResponse.plaintext as Buffer;

            if (dek.length !== 32) {
                throw new ValidationError(
                    `Invalid DEK length: ${dek.length} bytes. Expected 32 bytes for AES-256-GCM`,
                    ErrorCodes.VALIDATION.INVALID_DEK
                );
            }

            return dek;
        } catch (error) {
            if (error instanceof ValidationError || error instanceof EncryptionError) {
                throw error;
            }
            throw new EncryptionError(
                `Failed to decrypt DEK: ${error instanceof Error ? error.message : 'Unknown error'}`,
                ErrorCodes.ENCRYPTION.DEK_DECRYPTION_ERROR
            );
        }
    }
}

export default new KMSService(); 