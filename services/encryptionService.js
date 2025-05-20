const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const kmsService = require('./kmsService');
const secretManagerService = require('./secretManagerService');
const UserKeyDetails = require('../models/UserKeyDetails');
const createHash = require('../utils/createHash');

class EncryptionService {
    constructor() {
        this.config = JSON.parse(fs.readFileSync(path.join(__dirname, '../config/encryption.json'), 'utf8'));
    }

    // Generate a new Data Encryption Key (DEK)
    generateDEK(length = 32) {
        return crypto.randomBytes(length);
    }

    // Encrypt a single field using DEK
    async encryptField(fieldName, value, dek, username) {
        if (!value) return null;

        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);

        let encrypted = cipher.update(value, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();

        return {
            [`${fieldName}`]: encrypted,
            [`${fieldName}_iv`]: iv.toString('hex'),
            [`${fieldName}_auth_tag`]: authTag.toString('hex')
        };
    }

    // Decrypt a single field using its metadata
    async decryptField(fieldName, data) {
        if (!data[fieldName]) return null;

        // Get the secretId from UserKeyDetails
        const userKeyDetails = await UserKeyDetails.findOne({
            where: { userId: data.id }
        });
        console.log("🚀 ~ EncryptionService ~ decryptField ~ userKeyDetails:", userKeyDetails)

        if (!userKeyDetails) {
            throw new Error('No key details found for user');
        }

        // Get the encrypted DEK from Secret Manager
        const encryptedDEK = await secretManagerService.getSecret(userKeyDetails.dataValues.secretId);

        // Decrypt the DEK using KMS with the keyMetadata
        const dek = await kmsService.decryptDEK({
            encryptedDEKData: encryptedDEK,
            keyMetadata: {
                locationId: userKeyDetails.dataValues.locationId,
                keyRingId: userKeyDetails.dataValues.keyRingId,
                keyId: userKeyDetails.dataValues.keyId
            }
        });

        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            dek,
            Buffer.from(data[`${fieldName}_iv`], 'hex')
        );

        decipher.setAuthTag(Buffer.from(data[`${fieldName}_auth_tag`], 'hex'));

        let decrypted = decipher.update(data[fieldName], 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        console.log("🚀 ~ EncryptionService ~ decryptField ~ decrypted:", decrypted)

        return decrypted;
    }

    // Encrypt object fields based on configuration
    async encryptObject(modelName, data) {
        const modelConfig = this.config.encryptedFields[modelName];
        if (!modelConfig) return data;

        const encryptedData = { ...data };
        const username = data.username;

        // create hash of the email
        const emailHash = createHash(encryptedData.email);
        encryptedData.email_hash = emailHash;

        //DEK generated as per document
        const dek = this.generateDEK(modelConfig.dekLength);
        // Encrypt each field with same DEK
        for (const field of modelConfig.fields) {
            if (data[field]) {
                try {
                    const fieldData = await this.encryptField(field, data[field], dek, username);
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

        // Encrypt the DEK with KMS
        const { encryptedDEK, locationId, keyRingId, keyId } = await kmsService.encryptDEK(dek, username);

        // now save the encryptedDEK in gcp secret manager
        const secretId = `secret-${username}-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        await secretManagerService.createSecret(secretId, encryptedDEK);

        return {
            encryptedData,
            keyMetadata: {
                locationId,
                keyRingId,
                keyId,
                secretId
            }
        };
    }

    // Decrypt object fields based on configuration
    async decryptObject(modelName, data) {
        console.log("🚀 ~ EncryptionService ~ decryptObject ~ data:", data)
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
                delete decryptedData[`${field}_dek`];
                delete decryptedData[`${field}_auth_tag`];
            }
        }

        console.log("🚀 ~ EncryptionService ~ decryptObject ~ decryptedData:", decryptedData)
        return decryptedData;
    }

    // New method to create UserKeyDetails after user creation
    async createUserKeyDetails(userId, keyDetails) {
        return await UserKeyDetails.create({
            userId,
            username: keyDetails.username,
            locationId: keyDetails.locationId,
            keyRingId: keyDetails.keyRingId,
            keyId: keyDetails.keyId,
            secretId: keyDetails.secretId
        });
    }
}

module.exports = new EncryptionService(); 