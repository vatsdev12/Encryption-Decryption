import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import kmsService from './kmsService';
import secretManagerService from './secretManagerService';
import createHash from '../utils/createHash';
import {
    EncryptionConfig,
    KeyMetadata,
    EncryptedFieldData,
    EncryptedObjectResult,
    EntityKeyDetails,
    EntityKeyDetailsResult
} from '../types/encryption';

class EncryptionService {
    private config: EncryptionConfig;

    constructor() {
        const configPath = process.env.CONFIG_PATH || path.join(process.cwd(), 'src/config/encryption.json');
        this.config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    }

    /**
     * Generates a random Data Encryption Key (DEK) of specified length
     * @param length - Length of the key in bytes (default: 32)
     * @returns Buffer containing the generated key
     */
    generateDEK(length: number = 32): Buffer {
        return crypto.randomBytes(length);
    }

    /**
     * Encrypts a single field using AES-256-GCM encryption
     * @param fieldName - Name of the field to encrypt
     * @param value - Value to encrypt
     * @param dek - Data Encryption Key to use
     * @returns Object containing encrypted value, IV, and auth tag
     */
    async encryptField(fieldName: string, value: string, dek: Buffer): Promise<EncryptedFieldData | null> {
        if (!value) return null;

        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);

        let encrypted = cipher.update(value, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();

        return {
            [`${fieldName}_encrypted`]: encrypted,
            [`${fieldName}_iv`]: iv.toString('hex'),
            [`${fieldName}_auth_tag`]: authTag.toString('hex')
        };
    }

    /**
     * Decrypts a single field using AES-256-GCM decryption
     * @param fieldName - Name of the field to decrypt
     * @param data - Object containing encrypted data and metadata
     * @param dek - Data Encryption Key to use
     * @returns Decrypted value or null if field doesn't exist
     */
    async decryptField(fieldName: string, data: any, dek: Buffer): Promise<string | null> {
        const encryptedFieldName = `${fieldName}_encrypted`;
        if (!data[encryptedFieldName]) return null;

        try {
            const decipher = crypto.createDecipheriv(
                'aes-256-gcm',
                dek,
                Buffer.from(data[`${fieldName}_iv`], 'hex')
            );

            decipher.setAuthTag(Buffer.from(data[`${fieldName}_auth_tag`], 'hex'));

            let decrypted = decipher.update(data[encryptedFieldName], 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            return decrypted;
        } catch (error) {
            console.error(`Error decrypting field ${fieldName}:`, error);
            return data[fieldName] || null; // Fallback to original field if decryption fails
        }
    }

    /**
     * Handles encryption of multiple fields using the same DEK
     * @param modelConfig - Encryption configuration for the model
     * @param data - Data to encrypt
     * @param dek - Data Encryption Key to use
     * @returns Object containing encrypted data
     */
    private async handleFieldEncryption(
        modelConfig: any,
        data: any,
        dek: Buffer
    ): Promise<any> {
        const encryptedData = { ...data };

        for (const field of modelConfig.Encrypt) {
            if (data[field.key]) {
                try {
                    const fieldData = await this.encryptField(field.key, data[field.key], dek);
                    if (field.shouldHash) {
                        const hash = createHash(data[field.key]);
                        encryptedData[`${field.key}_hash`] = hash;
                    }
                    if (fieldData) {
                        Object.assign(encryptedData, fieldData);
                    }
                } catch (error) {
                    console.error(`Error encrypting field ${field.key}:`, error);
                    encryptedData[field.key] = data[field.key];
                }
            }
        }

        return encryptedData;
    }

    /**
     * Resolves DEK from entity key details, handling both cached and non-cached scenarios
     * @param entityKeyDetails - Entity's key details containing KMS metadata
     * @returns Object containing decrypted DEK and key metadata
     */
    private async resolveDEKFromEntityKeyDetails(entityKeyDetails: EntityKeyDetails): Promise<{ dek: Buffer, metadata: KeyMetadata }> {
        if (!entityKeyDetails.secretId || !entityKeyDetails.locationId || !entityKeyDetails.keyRingId || !entityKeyDetails.keyId || !entityKeyDetails.keyVersion) {
            throw new Error('Missing required key details');
        }

        let encryptedDEK = entityKeyDetails.encryptedDEK;

        if (!encryptedDEK) {
            encryptedDEK = await secretManagerService.getSecret(entityKeyDetails.secretId);
        }

        const dek = await kmsService.decryptDEK({
            encryptedDEKData: encryptedDEK,
            keyMetadata: {
                locationId: entityKeyDetails.locationId,
                keyRingId: entityKeyDetails.keyRingId,
                keyId: entityKeyDetails.keyId,
                keyVersion: entityKeyDetails.keyVersion
            }
        });

        return {
            dek,
            metadata: {
                locationId: entityKeyDetails.locationId,
                keyRingId: entityKeyDetails.keyRingId,
                keyId: entityKeyDetails.keyId,
                secretId: entityKeyDetails.secretId,
                keyVersion: entityKeyDetails.keyVersion,
                encryptedDEK
            }
        };
    }

    /**
     * Encrypts an object's fields based on model configuration
     * @param modelName - Name of the model being encrypted
     * @param data - Data to encrypt
     * @param kmsKeyName - Optional KMS key name for new encryption
     * @param entityKeyDetailsResult - Optional entity key details for existing encryption
     * @returns Object containing encrypted data and key metadata
     */
    async encryptObject(
        modelName: string,
        data: any,
        clientName?: string,
        entityKeyDetailsResult?: EntityKeyDetailsResult
    ): Promise<EncryptedObjectResult> {
        const modelConfig = this.config.encryptedFields[modelName];
        if (!modelConfig) return { encryptedData: data, keyMetadata: {} as KeyMetadata };

        const secretId = `secret-${clientName}`;

        if (entityKeyDetailsResult?.keyDetails) {
            const { keyDetails } = entityKeyDetailsResult;

            if (keyDetails.locationId && keyDetails.keyRingId && keyDetails.keyId && keyDetails.secretId && keyDetails.keyVersion) {
                const { dek, metadata } = await this.resolveDEKFromEntityKeyDetails(keyDetails);
                const encryptedData = await this.handleFieldEncryption(modelConfig, data, dek);
                return { encryptedData, keyMetadata: metadata };
            }
        }

        // No cached or entity key details - create new DEK
        const dek = this.generateDEK();
        const encryptedData = await this.handleFieldEncryption(modelConfig, data, dek);

        const { encryptedDEK, locationId, keyRingId, keyId, keyVersion } = await kmsService.encryptDEK(dek, clientName);
        await secretManagerService.createSecret(secretId, {
            encryptedDEK,
            locationId,
            keyRingId,
            keyId,
            keyVersion
        });

        return {
            encryptedData,
            keyMetadata: {
                locationId,
                keyRingId,
                keyId,
                secretId,
                encryptedDEK,
                keyVersion
            }
        };
    }

    /**
     * Decrypts an object's fields based on model configuration
     * @param modelName - Name of the model being decrypted
     * @param data - Data to decrypt
     * @param entityKeyDetailsResult - Optional entity key details for decryption
     * @returns Object containing decrypted data and optional encrypted DEK
     */
    async decryptObject(modelName: string, data: any, entityKeyDetailsResult?: EntityKeyDetailsResult): Promise<{ decryptedData: any, encryptedDEK?: Buffer }> {
        const modelConfig = this.config.encryptedFields[modelName];
        if (!modelConfig) return { decryptedData: data };

        const decryptedData = { ...data };
        let encryptedDEK: Buffer | undefined;

        if (entityKeyDetailsResult?.keyDetails) {
            const { keyDetails } = entityKeyDetailsResult;
            if (keyDetails.locationId && keyDetails.keyRingId && keyDetails.keyId && keyDetails.secretId && keyDetails.keyVersion) {
                const { dek, metadata } = await this.resolveDEKFromEntityKeyDetails(keyDetails);
                encryptedDEK = metadata.encryptedDEK || undefined;

                for (const field of modelConfig.Decrypt) {
                    const encryptedFieldName = `${field.key}_encrypted`;
                    if (data[encryptedFieldName]) {
                        try {
                            const decryptedValue = await this.decryptField(field.key, data, dek);
                            if (decryptedValue !== null) {
                                decryptedData[encryptedFieldName] = decryptedValue;
                                delete decryptedData[`${field.key}_iv`];
                                delete decryptedData[`${field.key}_auth_tag`];
                            }
                        } catch (error) {
                            console.error(`Error decrypting field ${field.key}:`, error);
                            // Keep original field if decryption fails
                            decryptedData[encryptedFieldName] = data[field.key];
                        }
                    }
                }
            }
        }

        return { decryptedData, encryptedDEK };
    }
}

export default new EncryptionService();
