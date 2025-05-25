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
    EntityKeyDetailsResult,
    EncryptObjectParams
} from '../types/encryption';
import {
    ConfigurationError,
    EncryptionError,
    ValidationError,
    ErrorCodes
} from '../types/errors';



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
     * Encrypts an object's fields based on model configuration
     * @param params - Object containing required parameters for encryption
     * @returns Object containing encrypted data and key metadata
     * @throws {ConfigurationError} When encryption configuration is missing
     * @throws {EncryptionError} When encryption operations fail
     * @throws {ValidationError} When required parameters are missing
     */
    async encryptObject({
        modelName,
        data,
        clientName,
        entityKeyDetailsResult
    }: EncryptObjectParams): Promise<EncryptedObjectResult> {
        try {
            if (!modelName) {
                throw new ValidationError(
                    'Model name is required',
                    ErrorCodes.VALIDATION.MISSING_REQUIRED_FIELD
                );
            }

            if (!data) {
                throw new ValidationError(
                    'Data to encrypt is required',
                    ErrorCodes.VALIDATION.MISSING_REQUIRED_FIELD
                );
            }

            const modelConfig = this.config.encryptedFields[modelName];
            if (!modelConfig) {
                throw new ConfigurationError(
                    `Encryption configuration not found for model ${modelName}`,
                    ErrorCodes.CONFIGURATION.MISSING_CONFIG
                );
            }

            const secretId = `secret-${clientName}`;

            if (entityKeyDetailsResult?.keyDetails) {
                try {
                    const { keyDetails } = entityKeyDetailsResult;

                    if (!keyDetails.locationId || !keyDetails.keyRingId || !keyDetails.keyId ||
                        !keyDetails.secretId || !keyDetails.keyVersion) {
                        throw new ValidationError(
                            'Missing required key details',
                            ErrorCodes.VALIDATION.MISSING_REQUIRED_FIELD
                        );
                    }

                    const { dek, metadata } = await this.resolveDEKFromEntityKeyDetails(keyDetails);
                    const encryptedData = await this.handleFieldEncryption(modelConfig, data, dek);
                    return { encryptedData, keyMetadata: metadata };
                } catch (error) {
                    throw new EncryptionError(
                        `Failed to use existing key details: ${error instanceof Error ? error.message : 'Unknown error'}`,
                        ErrorCodes.ENCRYPTION.KEY_DETAILS_ERROR
                    );
                }
            }

            // No cached or entity key details - create new DEK
            try {
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
            } catch (error) {
                throw new EncryptionError(
                    `Failed to create new encryption: ${error instanceof Error ? error.message : 'Unknown error'}`,
                    ErrorCodes.ENCRYPTION.CREATION_ERROR
                );
            }
        } catch (error) {
            if (error instanceof EncryptionError ||
                error instanceof ConfigurationError ||
                error instanceof ValidationError) {
                throw error;
            }
            throw new EncryptionError(
                `Unexpected error during encryption: ${error instanceof Error ? error.message : 'Unknown error'}`,
                ErrorCodes.ENCRYPTION.UNKNOWN_ERROR
            );
        }
    }

    /**
     * Handles encryption of multiple fields using the same DEK
     * @param modelConfig - Encryption configuration for the model
     * @param data - Data to encrypt
     * @param dek - Data Encryption Key to use
     * @returns Object containing encrypted data
     * @throws {EncryptionError} When field encryption fails
     */
    private async handleFieldEncryption(
        modelConfig: any,
        data: any,
        dek: Buffer
    ): Promise<any> {
        try {
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
                        throw new EncryptionError(
                            `Failed to encrypt field ${field.key}: ${error instanceof Error ? error.message : 'Unknown error'}`,
                            ErrorCodes.ENCRYPTION.FIELD_ENCRYPTION_ERROR
                        );
                    }
                }
            }

            return encryptedData;
        } catch (error) {
            if (error instanceof EncryptionError) {
                throw error;
            }
            throw new EncryptionError(
                `Failed to handle field encryption: ${error instanceof Error ? error.message : 'Unknown error'}`,
                ErrorCodes.ENCRYPTION.FIELD_ENCRYPTION_ERROR
            );
        }
    }

    /**
     * Resolves DEK from entity key details, handling both cached and non-cached scenarios
     * @param entityKeyDetails - Entity's key details containing KMS metadata
     * @returns Object containing decrypted DEK and key metadata
     * @throws {ValidationError} When required key details are missing
     * @throws {EncryptionError} When DEK resolution fails
     */
    private async resolveDEKFromEntityKeyDetails(entityKeyDetails: EntityKeyDetails): Promise<{ dek: Buffer, metadata: KeyMetadata }> {
        try {
            if (!entityKeyDetails.secretId || !entityKeyDetails.locationId ||
                !entityKeyDetails.keyRingId || !entityKeyDetails.keyId ||
                !entityKeyDetails.keyVersion) {
                throw new ValidationError(
                    'Missing required key details',
                    ErrorCodes.VALIDATION.MISSING_REQUIRED_FIELD
                );
            }

            let encryptedDEK = entityKeyDetails.encryptedDEK;

            if (!encryptedDEK) {
                try {
                    encryptedDEK = await secretManagerService.getSecret(entityKeyDetails.secretId);
                } catch (error) {
                    throw new EncryptionError(
                        `Failed to retrieve secret: ${error instanceof Error ? error.message : 'Unknown error'}`,
                        ErrorCodes.ENCRYPTION.SECRET_RETRIEVAL_ERROR
                    );
                }
            }

            try {
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
            } catch (error) {
                throw new EncryptionError(
                    `Failed to decrypt DEK: ${error instanceof Error ? error.message : 'Unknown error'}`,
                    ErrorCodes.ENCRYPTION.DEK_DECRYPTION_ERROR
                );
            }
        } catch (error) {
            if (error instanceof ValidationError || error instanceof EncryptionError) {
                throw error;
            }
            throw new EncryptionError(
                `Failed to resolve DEK: ${error instanceof Error ? error.message : 'Unknown error'}`,
                ErrorCodes.ENCRYPTION.DEK_RESOLUTION_ERROR
            );
        }
    }

    /**
     * Decrypts an object's fields based on model configuration
     * @param params - Object containing required parameters for decryption
     * @returns Object containing decrypted data and optional encrypted DEK
     * @throws {ConfigurationError} When encryption configuration is missing
     * @throws {EncryptionError} When decryption operations fail
     * @throws {ValidationError} When required parameters are missing
     */
    async decryptObject({
        modelName,
        data,
        entityKeyDetailsResult
    }: {
        modelName: string;
        data: any;
        entityKeyDetailsResult?: EntityKeyDetailsResult;
    }): Promise<{ decryptedData: any, encryptedDEK?: Buffer }> {
        try {
            if (!modelName) {
                throw new ValidationError(
                    'Model name is required',
                    ErrorCodes.VALIDATION.MISSING_REQUIRED_FIELD
                );
            }

            if (!data) {
                throw new ValidationError(
                    'Data to decrypt is required',
                    ErrorCodes.VALIDATION.MISSING_REQUIRED_FIELD
                );
            }

            const modelConfig = this.config.encryptedFields[modelName];
            if (!modelConfig) {
                throw new ConfigurationError(
                    `Encryption configuration not found for model ${modelName}`,
                    ErrorCodes.CONFIGURATION.MISSING_CONFIG
                );
            }

            const decryptedData = { ...data };
            let encryptedDEK: Buffer | undefined;

            if (entityKeyDetailsResult?.keyDetails) {
                try {
                    const { keyDetails } = entityKeyDetailsResult;

                    if (!keyDetails.locationId || !keyDetails.keyRingId || !keyDetails.keyId ||
                        !keyDetails.secretId || !keyDetails.keyVersion) {
                        throw new ValidationError(
                            'Missing required key details',
                            ErrorCodes.VALIDATION.MISSING_REQUIRED_FIELD
                        );
                    }

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
                                console.warn(`Failed to decrypt field ${field.key}:`, error);
                                decryptedData[encryptedFieldName] = data[field.key];
                                // throw new EncryptionError(
                                //     `Failed to decrypt field ${field.key}: ${error instanceof Error ? error.message : 'Unknown error'}`,
                                //     ErrorCodes.ENCRYPTION.FIELD_DECRYPTION_ERROR
                                // );
                            }
                        }
                    }
                } catch (error) {
                    if (error instanceof ValidationError || error instanceof EncryptionError) {
                        throw error;
                    }
                    // throw new EncryptionError(
                    //     `Failed to process key details: ${error instanceof Error ? error.message : 'Unknown error'}`,
                    //     ErrorCodes.ENCRYPTION.KEY_DETAILS_ERROR
                    // );
                }
            }

            return { decryptedData, encryptedDEK };
        } catch (error) {
            if (error instanceof ConfigurationError ||
                error instanceof EncryptionError ||
                error instanceof ValidationError) {
                throw error;
            }
            throw new EncryptionError(
                `Unexpected error during decryption: ${error instanceof Error ? error.message : 'Unknown error'}`,
                ErrorCodes.ENCRYPTION.UNKNOWN_ERROR
            );
        }
    }
}

export default new EncryptionService();
