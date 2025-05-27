import fs from 'fs';
import path from 'path';
import kmsService from './kmsService';
import secretManagerService from './secretManagerService';
import {
    decryptField,
    handleFieldEncryption,
} from '../utils/encryptionUtils';
import {
    EncryptionConfig,
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
        const configPath = process.env.CONFIG_PATH || path.join(process.cwd(), 'config/encryption.json');
        this.config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
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
        entityKeyDetailsResult
    }: EncryptObjectParams): Promise<{encryptedData:any,encryptedDEK:Buffer}> {
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

            if (!entityKeyDetailsResult?.kmsPath) {
                throw new ValidationError(
                    'Entity key details are required',
                    ErrorCodes.VALIDATION.MISSING_REQUIRED_FIELD
                );
            }

            try {
                const { kmsPath, secretId, secretNamePath, encryptedDEK } = entityKeyDetailsResult;

                if (!kmsPath || !secretId || !secretNamePath) {
                    throw new ValidationError(
                        'Missing required key details',
                        ErrorCodes.VALIDATION.MISSING_REQUIRED_FIELD
                    );
                }

                const { dek, encryptedDEK: encryptedDEKFromSecret } = await this.resolveDEKFromEntityKeyDetails({ kmsPath, secretId, secretNamePath, encryptedDEK });
                const encryptedData = await handleFieldEncryption(modelName, data, dek);
                return {
                    encryptedData,
                    encryptedDEK: encryptedDEKFromSecret
                };
            } catch (error) {
                throw new EncryptionError(
                    `Failed to use existing key details: ${error instanceof Error ? error.message : 'Unknown error'}`,
                    ErrorCodes.ENCRYPTION.KEY_DETAILS_ERROR
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
     * Resolves DEK from entity key details, handling both cached and non-cached scenarios
     * @param entityKeyDetails - Entity's key details containing KMS metadata
     * @returns Object containing decrypted DEK and key metadata
     * @throws {ValidationError} When required key details are missing
     * @throws {EncryptionError} When DEK resolution fails
     */
    private async resolveDEKFromEntityKeyDetails(entityKeyDetails: EntityKeyDetailsResult): Promise<{ dek: Buffer, encryptedDEK: Buffer }> {
        try {
            if (!entityKeyDetails.secretId || !entityKeyDetails.kmsPath ||
                !entityKeyDetails.secretNamePath || !entityKeyDetails.encryptedDEK) {
                throw new ValidationError(
                    'Missing required key details',
                    ErrorCodes.VALIDATION.MISSING_REQUIRED_FIELD
                );
            }

            let encryptedDEK = entityKeyDetails.encryptedDEK;

            if (!encryptedDEK) {
                try {
                    encryptedDEK = await secretManagerService.getSecret(entityKeyDetails.secretNamePath);
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
                    kmsPath: entityKeyDetails.kmsPath,
                });

                return { dek, encryptedDEK };
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
        entityKeyDetailsResult: EntityKeyDetailsResult;
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
            let encryptedDEKFromSecret: Buffer | undefined;

            if (entityKeyDetailsResult?.kmsPath) {
                try {
                    const { kmsPath } = entityKeyDetailsResult;

                    if (!kmsPath) {
                        throw new ValidationError(
                            'Missing required key details',
                            ErrorCodes.VALIDATION.MISSING_REQUIRED_FIELD
                        );
                    }

                    const { dek, encryptedDEK } = await this.resolveDEKFromEntityKeyDetails(entityKeyDetailsResult);
                    encryptedDEKFromSecret = encryptedDEK;

                    for (const field of modelConfig.Decrypt) {
                        const encryptedFieldName = `${field.key}_encrypted`;
                        if (data[encryptedFieldName]) {
                            try {
                                const decryptedValue = await decryptField(field.key, data, dek);
                                if (decryptedValue !== null) {
                                    decryptedData[encryptedFieldName] = decryptedValue;
                                    delete decryptedData[`${field.key}_iv`];
                                    delete decryptedData[`${field.key}_auth_tag`];
                                }
                            } catch (error) {
                                console.warn(`Failed to decrypt field ${field.key}:`, error);
                                decryptedData[encryptedFieldName] = data[field.key];
                            }
                        }
                    }
                } catch (error) {
                    if (error instanceof ValidationError || error instanceof EncryptionError) {
                        throw error;
                    }
                }
            }

            return { decryptedData, encryptedDEK: encryptedDEKFromSecret };
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
