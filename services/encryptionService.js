const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const kmsService = require('./kmsService');
const secretManagerService = require('./secretManagerService');
const { ClientKey } = require('../models');

class EncryptionService {
    constructor() {
        this.config = JSON.parse(fs.readFileSync(path.join(__dirname, '../config/encryption.json'), 'utf8'));
        this.dekCache = new Map(); // Cache for DEK keys
        this.cacheTTL = 3600000; // Cache TTL in milliseconds (1 hour)
    }

    // Generate a new Data Encryption Key (DEK)
    generateDEK(length = 32) {
        return crypto.randomBytes(length);
    }

    // Generate a unique secret ID for a document
    generateSecretId(modelName, userId) {
        const id = userId || `temp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        return `${modelName.toLowerCase()}_document_${id}_dek`;
    }

    // Get DEK from cache or fetch it
    async getDEKFromCache(clientId) {
        const cacheKey = `dek_${clientId}`;
        const cachedData = this.dekCache.get(cacheKey);

        if (cachedData && Date.now() - cachedData.timestamp < this.cacheTTL) {
            console.log(`Using cached DEK for client ${clientId}`);
            return cachedData.dek;
        }

        // If not in cache or expired, fetch from database and Secret Manager
        const clientKey = await ClientKey.findOne({
            where: {
                client_id: clientId,
                active: true
            },
            order: [['key_version', 'DESC']]
        });

        if (!clientKey) {
            throw new Error('Client key not found');
        }

        const encryptedDEKBase64 = await secretManagerService.getSecret(clientKey.secret_key);
        if (!encryptedDEKBase64) {
            throw new Error('Could not retrieve DEK from Secret Manager');
        }

        const encryptedDEK = Buffer.from(encryptedDEKBase64, 'base64');
        const dek = await kmsService.decryptDEK({ encryptedDEK });

        // Store in cache
        this.dekCache.set(cacheKey, {
            dek,
            timestamp: Date.now()
        });

        console.log(`Cached DEK for client ${clientId}`);
        return dek;
    }

    // Get or create client key
    async getClientKey(clientId) {
        try {
            // Get the latest active key for the client
            const clientKey = await ClientKey.findOne({
                where: {
                    client_id: clientId,
                    active: true
                },
                order: [['key_version', 'DESC']]
            });

            if (clientKey) {
                // Try to get DEK from cache first
                try {
                    const dek = await this.getDEKFromCache(clientId);
                    return dek;
                } catch (error) {
                    console.error('Error getting DEK from cache:', error);
                    // If cache fails, proceed with normal flow
                }
            }

            // Generate new key if none exists
            const dek = this.generateDEK();
            const encryptedDEK = await kmsService.encryptDEK(dek);
            const keyVersion = 1;

            // Store the encrypted DEK in Secret Manager
            const secretId = this.generateSecretId('User', clientId);
            await secretManagerService.createSecret(secretId, encryptedDEK.encryptedDEK.toString('base64'));
            console.log(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
            // Store the secret ID in client_keys table
            await ClientKey.create({
                client_id: clientId,
                key_version: keyVersion,
                secret_key: secretId,
                active: true
            });

            // Cache the new DEK
            const cacheKey = `dek_${clientId}`;
            this.dekCache.set(cacheKey, {
                dek,
                timestamp: Date.now()
            });

            return dek;
        } catch (error) {
            console.error('Error getting client key:', error);
            throw error;
        }
    }

    // Clear DEK from cache
    clearDEKFromCache(clientId) {
        const cacheKey = `dek_${clientId}`;
        this.dekCache.delete(cacheKey);
        console.log(`Cleared DEK cache for client ${clientId}`);
    }

    // Encrypt a single field
    async encryptField(fieldName, value, dek) {
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

    // Decrypt a single field
    async decryptField(fieldName, value, dek, iv, authTag) {
        if (!value) return null;

        try {
            const decipher = crypto.createDecipheriv('aes-256-gcm', dek, iv);
            decipher.setAuthTag(authTag);

            let decrypted = decipher.update(value, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            return decrypted;
        } catch (error) {
            console.error(`Error decrypting field ${fieldName}:`, error);
            throw error;
        }
    }

    // Encrypt object fields based on configuration
    async encryptObject(modelName, data) {
        try {
            const modelConfig = this.config.encryptedFields[modelName];
            if (!modelConfig) return data;

            const encryptedData = { ...data };
            const clientId = data.id;

            // Get or create client key (now uses cache)
            const dek = await this.getClientKey(clientId);

            // Encrypt each field
            for (const field of modelConfig.fields) {
                if (data[field]) {
                    try {
                        const fieldData = await this.encryptField(field, data[field], dek);
                        if (fieldData) {
                            Object.assign(encryptedData, fieldData);
                        }
                    } catch (error) {
                        console.error(`Error encrypting field ${field}:`, error);
                        encryptedData[field] = data[field];
                    }
                }
            }

            return encryptedData;
        } catch (error) {
            console.error('Error encrypting document:', error);
            throw error;
        }
    }

    // Decrypt object fields based on configuration
    async decryptObject(modelName, data) {
        const modelConfig = this.config.encryptedFields[modelName];
        if (!modelConfig) return data;

        const decryptedData = { ...data };

        try {
            const clientId = data.id;

            // Get DEK from cache or fetch it
            const dek = await this.getDEKFromCache(clientId);

            // Decrypt each field
            for (const field of modelConfig.fields) {
                if (data[field]) {
                    try {
                        const iv = Buffer.from(data[`${field}_iv`], 'hex');
                        const authTag = Buffer.from(data[`${field}_auth_tag`], 'hex');
                        const decryptedValue = await this.decryptField(field, data[field], dek, iv, authTag);
                        if (decryptedValue !== null) {
                            decryptedData[field] = decryptedValue;
                        }
                    } catch (error) {
                        console.error(`Error decrypting field ${field}:`, error);
                        decryptedData[field] = data[field];
                    }
                }
            }

            // Remove metadata fields
            for (const field of modelConfig.fields) {
                delete decryptedData[`${field}_iv`];
                delete decryptedData[`${field}_auth_tag`];
            }

            return decryptedData;
        } catch (error) {
            console.error('Error decrypting document:', error);
            return data;
        }
    }
}

module.exports = new EncryptionService(); 