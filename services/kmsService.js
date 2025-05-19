const { KeyManagementServiceClient } = require('@google-cloud/kms').v1;
const crypto = require('crypto');
const userKeys = require('../config/Userkeys.json');

class KMSService {
    constructor() {
        this.isDevelopment = process.env.NODE_ENV === 'development' || !process.env.GOOGLE_CLOUD_PROJECT;
        console.log("🚀 ~ KMSService ~ constructor ~ isDevelopment:", this.isDevelopment)

        if (!this.isDevelopment) {
            this.client = new KeyManagementServiceClient();
            this.projectId = process.env.GOOGLE_CLOUD_PROJECT;
            this.locationId = process.env.KMS_LOCATION_ID || 'global';
            console.log("🚀 ~ KMSService ~ constructor ~ keyName:", this.keyName);
        } else {
            // Development mode: use a local key
            this.localKey = crypto.scryptSync(
                process.env.LOCAL_ENCRYPTION_KEY || 'development-key',
                'salt',
                32
            );
        }
    }

    async encryptDEK(dek, username) {
        try {
            if (this.isDevelopment) {
                // Local encryption for development

                //get key details from userkeys.json
              
                const iv = crypto.randomBytes(16);
                const cipher = crypto.createCipheriv('aes-256-gcm', this.localKey, iv);

                let encryptedDEK = cipher.update(dek, 'binary', 'hex');
                encryptedDEK += cipher.final('hex');

                const authTag = cipher.getAuthTag();

                return {
                    encryptedDEK,
                    dekIV: iv.toString('hex'),
                    dekAuthTag: authTag.toString('hex')
                };
            }

            // Production: use Google Cloud KMS
             
            const keyDetails = userKeys[username];
            console.log("🚀 ~ KMSService ~ encryptDEK ~ keyDetails:", keyDetails)
            const keyName = this.client.cryptoKeyPath(
                this.projectId,
                keyDetails.locationId,
                keyDetails.keyRingId,
                keyDetails.keyId
            );
            const [encryptResponse] = await this.client.encrypt({
                name: keyName,
                plaintext: dek.toString('base64')
            });

            return {
                encryptedDEK: encryptResponse.ciphertext,
                dekIV: null,
                dekAuthTag: null
            };
        } catch (error) {
            console.error('Error encrypting DEK:', error);
            throw new Error('Failed to encrypt DEK');
        }
    }

    async decryptDEK({encryptedDEKData, username}) {
        console.log("🚀 ~ KMSService ~ decryptDEK ~ encryptedDEKData:", encryptedDEKData)
        console.log("🚀 ~ KMSService ~ decryptDEK ~ username:", username)
        // return;
        try {
            if (this.isDevelopment) {
                // Local decryption for development
                const decipher = crypto.createDecipheriv(
                    'aes-256-gcm',
                    this.localKey,
                    Buffer.from(encryptedDEKData.dekIV, 'hex')
                );

                decipher.setAuthTag(Buffer.from(encryptedDEKData.dekAuthTag, 'hex'));

                let decryptedDEK = decipher.update(encryptedDEKData.encryptedDEK, 'hex', 'binary');
                decryptedDEK += decipher.final('binary');

                return Buffer.from(decryptedDEK, 'binary');
            }
            const keyDetails = userKeys[username];
            console.log("🚀 ~ KMSService ~ decryptDEK ~ keyDetails:", keyDetails)

            const keyName = this.client.cryptoKeyPath(
                this.projectId,
                keyDetails.locationId,
                keyDetails.keyRingId,
                keyDetails.keyId
            );
            // Production: use Google Cloud KMS
            console.log("🚀 ~ KMSService ~ decryptDEK ~ keyName:", keyName);
            const [decryptResponse] = await this.client.decrypt({
                name: keyName,
                ciphertext: encryptedDEKData
            });

            return Buffer.from(decryptResponse.plaintext, 'base64');
        } catch (error) {
            console.error('Error decrypting DEK:', error);
            throw new Error('Failed to decrypt DEK');
        }
    }
}

module.exports = new KMSService(); 