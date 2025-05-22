import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import kmsService from './kmsService';
import secretManagerService from './secretManagerService';
import createHash from '../utils/createHash';

interface EncryptionConfig {
    encryptedFields: {
        [key: string]: {
            Encrypt: {
                key: string;
                shouldHash: boolean;
            }[];
            Decrypt: {
                key: string;
                shouldHash: boolean;
            }[];
        };
    };
}

interface KeyMetadata {
    locationId: string;
    keyRingId: string;
    keyId: string;
    secretId: string;
    encryptedDEK?: Buffer | null;
}

interface EncryptedFieldData {
    [key: string]: string;
}

interface EncryptedObjectResult {
    encryptedData: any;
    keyMetadata: KeyMetadata;
}

interface UserKeyDetails {
    locationId: string | null;
    keyRingId: string | null;
    keyId: string | null;
    secretId: string | null;
    encryptedDEK?: Buffer | null;
}

interface UserKeyDetailsResult {
    userKeyDetails: UserKeyDetails;
    isCached: boolean;
    isUserKeyDetails: boolean;
}

class EncryptionService {
    private config: EncryptionConfig;

    constructor() {
        const configPath = process.env.CONFIG_PATH || path.join(process.cwd(), 'src/config/encryption.json');
        this.config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    }

    // Generate a new Data Encryption Key (DEK)
    generateDEK(length: number = 32): Buffer {
        return crypto.randomBytes(length);
    }

    // Encrypt a single field using DEK
    async encryptField(fieldName: string, value: string, dek: Buffer): Promise<EncryptedFieldData | null> {
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

    // async getKeyDetails(userId: number): Promise<Buffer> {
    //     console.log('FETCHING THE USER KEY DETAILS')

    //     const encryptedDEK = await secretManagerService.getSecret(userKeyDetails.dataValues.secretId);

    //     const dek = await kmsService.decryptDEK({
    //         encryptedDEKData: encryptedDEK,
    //         keyMetadata: {
    //             locationId: userKeyDetails.dataValues.locationId,
    //             keyRingId: userKeyDetails.dataValues.keyRingId,
    //             keyId: userKeyDetails.dataValues.keyId
    //         }
    //     });
    //     console.log('DECRYPTED THE DEK')
    //     return dek;
    // }

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
    async encryptObject(modelName: string, data: any, kmsKeyName?: string, userKeyDetailsResult?: UserKeyDetailsResult): Promise<EncryptedObjectResult> {
        //Fetch the config for the model

        const modelConfig = this.config.encryptedFields[modelName];
        if (!modelConfig) return { encryptedData: data, keyMetadata: {} as KeyMetadata };

        const encryptedData = { ...data };
        console.log('FETCHED THE FIELDS TO ENCRYPT')
        const secretId = `secret-${kmsKeyName}`;

        const isUserKeyDetails = userKeyDetailsResult?.isUserKeyDetails;
        const isCached = userKeyDetailsResult?.isCached;
        const userKeyDetails = userKeyDetailsResult?.userKeyDetails;

        if (isCached && userKeyDetails) {
            //check if userKeyDetails has all the fields
            if (userKeyDetails.locationId && userKeyDetails.keyRingId && userKeyDetails.keyId && userKeyDetails.secretId && userKeyDetails.encryptedDEK) {
                //DEK generated as per document
                const dek = await kmsService.decryptDEK({
                    encryptedDEKData: userKeyDetails.encryptedDEK,
                    keyMetadata: {
                        locationId: userKeyDetails.locationId,
                        keyRingId: userKeyDetails.keyRingId,
                        keyId: userKeyDetails.keyId
                    }
                });
                console.log('DECRYPTED THE DEK')
                // encrypt the data
                console.log('ENCRYPTING THE FIELDs STARTED CACHED')
                for (const field of modelConfig.Encrypt) {
                    if (data[field.key]) {
                        try {
                            const fieldData = await this.encryptField(field.key, data[field.key], dek);
                            //hash the field if shouldHash is true
                            if (field.shouldHash) {
                                const hash = createHash(data[field.key]);
                                encryptedData[`${field.key}_hash`] = hash;
                            }
                            if (fieldData) {
                                // Merge the encrypted field data into the result
                                Object.assign(encryptedData, fieldData);
                            }
                        } catch (error) {
                            console.error(`Error encrypting field ${field.key}:`, error);
                            // Keep the original value if encryption fails
                            encryptedData[field.key] = data[field.key];
                        }
                    }
                }
                console.log('ENCRYPTED THE FIELDs ENDED CACHED')
                return {
                    encryptedData,
                    keyMetadata: {
                        locationId: userKeyDetails.locationId,
                        keyRingId: userKeyDetails.keyRingId,
                        keyId: userKeyDetails.keyId,
                        secretId: userKeyDetails.secretId
                    }
                };
            }
            if (userKeyDetails.locationId && userKeyDetails.keyRingId && userKeyDetails.keyId && userKeyDetails.secretId) {
                //DEK generated as per document
                const encryptedDEK = await secretManagerService.getSecret(userKeyDetails.secretId);
                const dek = await kmsService.decryptDEK({
                    encryptedDEKData: encryptedDEK,
                    keyMetadata: {
                        locationId: userKeyDetails.locationId,
                        keyRingId: userKeyDetails.keyRingId,
                        keyId: userKeyDetails.keyId
                    }
                });
                console.log('DECRYPTED THE DEK')
                // encrypt the data
                console.log('ENCRYPTING THE FIELDs STARTED CACHED')
                for (const field of modelConfig.Encrypt) {
                    if (data[field.key]) {
                        try {
                            const fieldData = await this.encryptField(field.key, data[field.key], dek);
                            if (fieldData) {
                                // Merge the encrypted field data into the result
                                Object.assign(encryptedData, fieldData);
                            }
                        } catch (error) {
                            console.error(`Error encrypting field ${field.key}:`, error);
                            // Keep the original value if encryption fails
                            encryptedData[field.key] = data[field.key];
                        }
                    }
                }
                console.log('ENCRYPTED THE FIELDs ENDED CACHED')
                return {
                    encryptedData,
                    keyMetadata: {
                        locationId: userKeyDetails.locationId,
                        keyRingId: userKeyDetails.keyRingId,
                        keyId: userKeyDetails.keyId,
                        secretId: userKeyDetails.secretId,
                        encryptedDEK: encryptedDEK
                    }
                };
            }
        }


        if (isUserKeyDetails && userKeyDetails) {
            //check if userKeyDetails has all the fields
            if (userKeyDetails.locationId && userKeyDetails.keyRingId && userKeyDetails.keyId && userKeyDetails.secretId) {
                const encryptedDEK = await secretManagerService.getSecret(userKeyDetails.secretId);

                //DEK generated as per document
                const dek = await kmsService.decryptDEK({
                    encryptedDEKData: encryptedDEK,
                    keyMetadata: {
                        locationId: userKeyDetails.locationId,
                        keyRingId: userKeyDetails.keyRingId,
                        keyId: userKeyDetails.keyId
                    }
                });
                console.log('DECRYPTED THE DEK')
                // encrypt the data
                console.log('ENCRYPTING THE FIELDs STARTED CACHED')
                for (const field of modelConfig.Encrypt) {
                    if (data[field.key]) {
                        try {
                            const fieldData = await this.encryptField(field.key, data[field.key], dek);
                            //hash the field if shouldHash is true
                            if (field.shouldHash) {
                                const hash = createHash(data[field.key]);
                                encryptedData[`${field.key}_hash`] = hash;
                            }
                            if (fieldData) {
                                // Merge the encrypted field data into the result
                                Object.assign(encryptedData, fieldData);
                            }
                        } catch (error) {
                            console.error(`Error encrypting field ${field.key}:`, error);
                            // Keep the original value if encryption fails
                            encryptedData[field.key] = data[field.key];
                        }
                    }
                }
                console.log('ENCRYPTED THE FIELDs ENDED CACHED')
                return {
                    encryptedData,
                    keyMetadata: {
                        locationId: userKeyDetails.locationId,
                        keyRingId: userKeyDetails.keyRingId,
                        keyId: userKeyDetails.keyId,
                        secretId: userKeyDetails.secretId
                    }
                };
            }
        }

        const dek = this.generateDEK();
        console.log('GENERATED DEK')

        // Encrypt each field with same DEK

        console.log('ENCRYPTING THE FIELDs STARTED')
        for (const field of modelConfig.Encrypt) {
            if (data[field.key]) {
                try {
                    const fieldData = await this.encryptField(field.key, data[field.key], dek);
                    //hash the field if shouldHash is true
                    if (field.shouldHash) {
                        const hash = createHash(data[field.key]);
                        encryptedData[`${field.key}_hash`] = hash;
                    }
                    if (fieldData) {
                        // Merge the encrypted field data into the result
                        Object.assign(encryptedData, fieldData);
                    }
                } catch (error) {
                    console.error(`Error encrypting field ${field.key}:`, error);
                    // Keep the original value if encryption fails
                    encryptedData[field.key] = data[field.key];
                }
            }
        }
        console.log('ENCRYPTED THE FIELDs ENDED')

        // Encrypt the DEK with KMS

        const { encryptedDEK, locationId, keyRingId, keyId } = await kmsService.encryptDEK(dek, kmsKeyName);
        console.log('ENCRYPTED THE DEK')

        // now save the encryptedDEK in gcp secret manager


        await secretManagerService.createSecret(secretId, {
            encryptedDEK: encryptedDEK,
            locationId: locationId,
            keyRingId: keyRingId,
            keyId: keyId
        });
        console.log('SAVED THE ENCRYPTED DEK IN GCP SECRET MANAGER')

        return {
            encryptedData,
            keyMetadata: {
                locationId: locationId,
                keyRingId: keyRingId,
                keyId: keyId,
                secretId: secretId,
                encryptedDEK: encryptedDEK
            },
        };
    }

    // // Decrypt object fields based on configuration
    async decryptObject(modelName: string, data: any, userKeyDetailsResult?: UserKeyDetailsResult): Promise<any> {
        const modelConfig = this.config.encryptedFields[modelName];
        if (!modelConfig) return data;
        console.log('FETCHED THE FIELDS TO DECRYPT')
        const decryptedData = { ...data };

        const isUserKeyDetails = userKeyDetailsResult?.isUserKeyDetails;
        const isCached = userKeyDetailsResult?.isCached;
        const userKeyDetails = userKeyDetailsResult?.userKeyDetails;
        let dek: Buffer | null = null;

        if (isCached && userKeyDetails) {
            //check if userKeyDetails has all the fields
            if (userKeyDetails.locationId && userKeyDetails.keyRingId && userKeyDetails.keyId && userKeyDetails.secretId && userKeyDetails.encryptedDEK) {
                //DEK generated as per document
                dek = await kmsService.decryptDEK({
                    encryptedDEKData: userKeyDetails.encryptedDEK,
                    keyMetadata: {
                        locationId: userKeyDetails.locationId,
                        keyRingId: userKeyDetails.keyRingId,
                        keyId: userKeyDetails.keyId
                    }
                });
            }
        }

        let encryptedDEK;
        if (isUserKeyDetails && userKeyDetails && dek === null) {
            //check if userKeyDetails has all the fields
            if (userKeyDetails.locationId && userKeyDetails.keyRingId && userKeyDetails.keyId && userKeyDetails.secretId) {
                //DEK generated as per document
                encryptedDEK = await secretManagerService.getSecret(userKeyDetails.secretId);
                dek = await kmsService.decryptDEK({
                    encryptedDEKData: encryptedDEK,
                    keyMetadata: {
                        locationId: userKeyDetails.locationId,
                        keyRingId: userKeyDetails.keyRingId,
                        keyId: userKeyDetails.keyId
                    }
                });
                console.log('DECRYPTED THE DEK')
            }
        }

        if (dek === null) {
            console.log('DEK is not found')
            return data;
        }

        // Decrypt each field separately
        console.log('DECRYPTING THE FIELDs STARTED')
        for (const field of modelConfig.Decrypt) {
            if (data[field.key]) {
                try {
                    const decryptedValue = await this.decryptField(field.key, data, dek);
                    if (decryptedValue !== null) {
                        decryptedData[field.key] = decryptedValue;
                    }
                } catch (error) {
                    console.error(`Error decrypting field ${field.key}:`, error);
                    // Keep the encrypted value if decryption fails
                    decryptedData[field.key] = data[field.key];
                }

                // Remove the encryption metadata fields
                delete decryptedData[`${field}_iv`];
                delete decryptedData[`${field}_dek`];
                delete decryptedData[`${field}_auth_tag`];
            }
        }

        return {
            decryptedData,
            encryptedDEK: encryptedDEK
        };
    }

    // New method to create UserKeyDetails after user creation
    // async createUserKeyDetails(userId: number, keyDetails: KeyMetadata): Promise<UserKeyDetails> {
    //     return await UserKeyDetails.create({
    //         userId,
    //         locationId: keyDetails.locationId,
    //         keyRingId: keyDetails.keyRingId,
    //         keyId: keyDetails.keyId,
    //         secretId: keyDetails.secretId
    //     });
    // }
}

export default new EncryptionService(); 