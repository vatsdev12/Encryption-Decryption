const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const kmsService = require('./kmsService');
const secretManagerService = require('./secretManagerService');

class EncryptionService {
    constructor() {
        this.config = JSON.parse(fs.readFileSync(path.join(__dirname, '../config/encryption.json'), 'utf8'));
    }

    // Generate a new Data Encryption Key (DEK)
    generateDEK(length = 32) {
        return crypto.randomBytes(length);
    }

    // Generate a unique secret ID for a field
    generateSecretId(modelName, fieldName, userId) {
        // For new records, use a temporary ID based on timestamp
        const id = userId || `temp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        return `${modelName.toLowerCase()}_${fieldName}_${id}_dek`;
    }

    // Encrypt a single field using DEK
    async encryptField(fieldName, value, dek, userId, modelName) {
        if (!value) return null;

        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);

        let encrypted = cipher.update(value, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();

        // Encrypt the DEK with KMS
        const encryptedDEK = await kmsService.encryptDEK(dek);

        // Store the encrypted DEK in Secret Manager
        const secretId = this.generateSecretId(modelName, fieldName, userId);
        await secretManagerService.createSecret(secretId, encryptedDEK.encryptedDEK.toString('base64'));

        return {
            [`${fieldName}`]: encrypted,
            [`${fieldName}_iv`]: iv.toString('hex'),
            [`${fieldName}_secret_id`]: secretId,
            [`${fieldName}_auth_tag`]: authTag.toString('hex'),
            [`${fieldName}_dek`]: encryptedDEK.encryptedDEK.toString('base64')
        };
    }

    // Decrypt a single field using its metadata
    async decryptField(fieldName, data) {
        if (!data[fieldName]) return null;

        try {
            let dek;

            // Check if we're using the new format (Secret Manager)
            if (data[`${fieldName}_secret_id`]) {
                const secretId = data[`${fieldName}_secret_id`];
                const encryptedDEKBase64 = await secretManagerService.getSecret(secretId);
                const encryptedDEK = Buffer.from(encryptedDEKBase64, 'base64');
                dek = await kmsService.decryptDEK({ encryptedDEK });
            }
            // Check if we're using the old format (direct DEK storage)
            else if (data[`${fieldName}_dek`]) {
                const encryptedDEK = Buffer.from(data[`${fieldName}_dek`], 'base64');
                dek = await kmsService.decryptDEK({ encryptedDEK });
            }
            else {
                throw new Error(`No encryption key found for field ${fieldName}`);
            }

            const decipher = crypto.createDecipheriv(
                'aes-256-gcm',
                dek,
                Buffer.from(data[`${fieldName}_iv`], 'hex')
            );

            decipher.setAuthTag(Buffer.from(data[`${fieldName}_auth_tag`], 'hex'));

            let decrypted = decipher.update(data[fieldName], 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            return decrypted;
        } catch (error) {
            console.error(`Error decrypting field ${fieldName}:`, error);
            throw error;
        }
    }

    // Encrypt object fields based on configuration
    async encryptObject(modelName, data) {
        const modelConfig = this.config.encryptedFields[modelName];
        if (!modelConfig) return data;

        const encryptedData = { ...data };

        // Encrypt each field separately
        for (const field of modelConfig.fields) {
            if (data[field]) {
                try {
                    const dek = this.generateDEK(modelConfig.dekLength);
                    const fieldData = await this.encryptField(field, data[field], dek, data.id, modelName);

                    if (fieldData) {
                        // Merge the encrypted field data into the result
                        Object.assign(encryptedData, fieldData);
                    }
                } catch (error) {
                    console.error(`Error encrypting field ${field}:`, error);
                    // Keep the original value if encryption fails
                    encryptedData[field] = data[field];
                }
            }
        }

        return encryptedData;
    }

    // Decrypt object fields based on configuration
    async decryptObject(modelName, data) {
        const modelConfig = this.config.encryptedFields[modelName];
        if (!modelConfig) return data;

        const decryptedData = { ...data };

        // Decrypt each field separately
        for (const field of modelConfig.fields) {
            if (data[field]) {
                try {
                    const decryptedValue = await this.decryptField(field, data);
                    if (decryptedValue !== null) {
                        decryptedData[field] = decryptedValue;
                    }
                } catch (error) {
                    console.error(`Error decrypting field ${field}:`, error);
                    // Keep the encrypted value if decryption fails
                    decryptedData[field] = data[field];
                }

                // Remove the encryption metadata fields
                delete decryptedData[`${field}_iv`];
                delete decryptedData[`${field}_secret_id`];
                delete decryptedData[`${field}_dek`];
                delete decryptedData[`${field}_auth_tag`];
            }
        }

        return decryptedData;
    }
}

module.exports = new EncryptionService(); 