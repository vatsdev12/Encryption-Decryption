import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import kmsService from './kmsService';
import secretManagerService from './secretManagerService';
import UserKeyDetails from '../models/UserKeyDetails';
import createHash from '../utils/createHash';

interface EncryptionConfig {
    encryptedFields: {
        [key: string]: {
            fields: string[];
            dekLength: number;
        };
    };
}

interface KeyMetadata {
    locationId: string;
    keyRingId: string;
    keyId: string;
    secretId: string;
}

interface EncryptedFieldData {
    [key: string]: string;
}

interface EncryptedObjectResult {
    encryptedData: any;
    keyMetadata: KeyMetadata;
}

class EncryptionService {
    private config: EncryptionConfig;

    constructor() {
        this.config = JSON.parse(fs.readFileSync(path.join(__dirname, '../config/encryption.json'), 'utf8'));
    }

    // Generate a new Data Encryption Key (DEK)
    generateDEK(length: number = 32): Buffer {
        return crypto.randomBytes(length);
    }

    // Encrypt a single field using DEK
    async encryptField(fieldName: string, value: string, dek: Buffer, username: string): Promise<EncryptedFieldData | null> {
        if (!value) return null;

        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);

        let encrypted = cipher.update(value, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();
        console.log('ENCRYPTED THE FIELD ', fieldName)
        return {
            [`${fieldName}`]: encrypted,
            [`${fieldName}_iv`]: iv.toString('hex'),
            [`${fieldName}_auth_tag`]: authTag.toString('hex')
        };
    }

    async getKeyDetails(userId: number): Promise<Buffer> {
        console.log('FETCHING THE USER KEY DETAILS')
        const userKeyDetails = await UserKeyDetails.findOne({
            where: { userId }
        });
        if (!userKeyDetails) {
            throw new Error('No key details found for user');
        }
        const encryptedDEK = await secretManagerService.getSecret(userKeyDetails.dataValues.secretId);

        const dek = await kmsService.decryptDEK({
            encryptedDEKData: encryptedDEK,
            keyMetadata: {
                locationId: userKeyDetails.dataValues.locationId,
                keyRingId: userKeyDetails.dataValues.keyRingId,
                keyId: userKeyDetails.dataValues.keyId
            }
        });
        console.log('DECRYPTED THE DEK')
        return dek;
    }

    // Decrypt a single field using its metadata
    async decryptField(fieldName: string, data: any, dek: Buffer): Promise<string | null> {
        console.log('DECRYPTING THE FIELD ', fieldName)
        if (!data[fieldName]) return null;

        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            dek,
            Buffer.from(data[`${fieldName}_iv`], 'hex')
        );

        decipher.setAuthTag(Buffer.from(data[`${fieldName}_auth_tag`], 'hex'));

        let decrypted = decipher.update(data[fieldName], 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    }

    // Encrypt object fields based on configuration
    async encryptObject(modelName: string, data: any): Promise<EncryptedObjectResult> {
        const modelConfig = this.config.encryptedFields[modelName];
        if (!modelConfig) return { encryptedData: data, keyMetadata: {} as KeyMetadata };

        const encryptedData = { ...data };
        const username = encryptedData.username;
        console.log('FETCHED THE FIELDS TO ENCRYPT')
        // create hash of the email
        const emailHash = createHash(encryptedData.email);
        encryptedData.email_hash = emailHash;
        console.log('CREATED HASH OF THE EMAIL')
        //DEK generated as per document
        const dek = this.generateDEK(modelConfig.dekLength);
        console.log('GENERATED DEK')
        // Encrypt each field with same DEK
        console.log('ENCRYPTING THE FIELDs STARTED')
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
        console.log('ENCRYPTED THE FIELDs ENDED')
        // Encrypt the DEK with KMS
        const { encryptedDEK, locationId, keyRingId, keyId } = await kmsService.encryptDEK(dek, username);
        console.log('ENCRYPTED THE DEK')
        // now save the encryptedDEK in gcp secret manager
        const secretId = `secret-${username}-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        await secretManagerService.createSecret(secretId, encryptedDEK);
        console.log('SAVED THE ENCRYPTED DEK IN GCP SECRET MANAGER')
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
    async decryptObject(modelName: string, data: any): Promise<any> {
        const modelConfig = this.config.encryptedFields[modelName];
        if (!modelConfig) return data;
        console.log('FETCHED THE FIELDS TO DECRYPT')
        const decryptedData = { ...data };

        // Get the secretId from UserKeyDetails
        const dek = await this.getKeyDetails(data.id);

        // Decrypt each field separately
        console.log('DECRYPTING THE FIELDs STARTED')
        for (const field of modelConfig.fields) {
            if (data[field]) {
                try {
                    const decryptedValue = await this.decryptField(field, data, dek);
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

        return decryptedData;
    }

    // New method to create UserKeyDetails after user creation
    async createUserKeyDetails(userId: number, keyDetails: KeyMetadata): Promise<UserKeyDetails> {
        return await UserKeyDetails.create({
            userId,
            locationId: keyDetails.locationId,
            keyRingId: keyDetails.keyRingId,
            keyId: keyDetails.keyId,
            secretId: keyDetails.secretId
        });
    }
}

export default new EncryptionService(); 