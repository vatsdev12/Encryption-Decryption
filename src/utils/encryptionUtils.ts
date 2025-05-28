import crypto from 'crypto';
import {
    EncryptionError,
    ErrorCodes
} from '../types/errors';

import {
    EncryptedFieldData,
    KeyDetailsObjectResult
} from '../types/encryption';
import kmsService from '../services/kmsService';
import secretManagerService from '../services/secretManagerService';
import createHash from './createHash';
import { getModelConfig } from './configUtils';

/**
 * Generates a random Data Encryption Key (DEK) of specified length
 * @param length - Length of the key in bytes (default: 32)
 * @returns Buffer containing the generated key
 */
export const generateDEK = (length: number = 32): Buffer => {
    return crypto.randomBytes(length);
};

/**
 * Encrypts a single field using AES-256-GCM encryption
 * @param fieldName - Name of the field to encrypt
 * @param value - Value to encrypt
 * @param dek - Data Encryption Key to use
 * @returns Object containing encrypted value, IV, and auth tag
 */
export const encryptField = async (
    fieldName: string,
    value: string,
    dek: Buffer
): Promise<EncryptedFieldData | null> => {
    if (!value) return null;

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);

    let encrypted = cipher.update(value, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return {
        [fieldName]: encrypted,
        [`${fieldName}_encrypted`]: encrypted,
        [`${fieldName}_iv`]: iv.toString('hex'),
        [`${fieldName}_auth_tag`]: authTag.toString('hex')
    };
};

/**
 * Decrypts a single field using AES-256-GCM decryption
 * @param fieldName - Name of the field to decrypt
 * @param data - Object containing encrypted data and metadata
 * @param dek - Data Encryption Key to use
 * @returns Decrypted value or null if field doesn't exist
 */
export const decryptField = async (
    fieldName: string,
    data: any,
    dek: Buffer
): Promise<string | null> => {
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
};

/**
 * Handles encryption of multiple fields using the same DEK
 * @param modelName - Name of the model to encrypt fields for
 * @param data - Data to encrypt
 * @param dek - Data Encryption Key to use
 * @returns Object containing encrypted data
 * @throws {EncryptionError} When field encryption fails
 * @throws {ConfigurationError} When model configuration is not found
 */
export const handleFieldEncryption = async (
    modelName: string,
    data: any,
    dek: Buffer
): Promise<any> => {
    try {
        const modelConfig = getModelConfig(modelName);
        const encryptedData = { ...data };

        for (const field of modelConfig.Encrypt) {
            if (data[field.key]) {
                try {
                    const fieldData = await encryptField(field.key, data[field.key], dek);
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
};

/**
 * Creates a new encryption with DEK generation and storage
 * @param modelName - Name of the model to encrypt
 * @param data - Data to encrypt
 * @param clientName - Name of the client for secret identification
 * @returns Object containing encrypted data and key metadata
 * @throws {EncryptionError} When encryption creation fails
 */
export const createNewEncryption = async (
    clientName: string,
): Promise<KeyDetailsObjectResult> => {
    try {
        const dek = generateDEK();

        const { encryptedDEK, kmsPath } = await kmsService.encryptDEK(dek, clientName);

        const secretId = `secret-${clientName}`;
        const { secretNamePath } = await secretManagerService.createSecret(secretId, {
            encryptedDEK,
            kmsPath
        });

        return {
            kmsPath,
            secretId,
            secretNamePath,
            encryptedDEK
        };
    } catch (error) {
        throw new EncryptionError(
            `Failed to create new encryption: ${error instanceof Error ? error.message : 'Unknown error'}`,
            ErrorCodes.ENCRYPTION.CREATION_ERROR
        );
    }
}; 