const { KeyManagementServiceClient } = require('@google-cloud/kms').v1;
const crypto = require('crypto');

class KMSService {
    constructor() {
        this.isDevelopment = process.env.NODE_ENV === 'development' || !process.env.GOOGLE_CLOUD_PROJECT;
        console.log("🚀 ~ KMSService ~ constructor ~ isDevelopment:", this.isDevelopment)

        if (!this.isDevelopment) {
            this.client = new KeyManagementServiceClient();
            this.projectId = process.env.GOOGLE_CLOUD_PROJECT;
            this.locationId = process.env.KMS_LOCATION_ID || 'global';
            this.keyRingId = process.env.KMS_KEY_RING_ID;
            this.keyId = process.env.KMS_KEY_ID;
            this.keyName = this.client.cryptoKeyPath(
                this.projectId,
                this.locationId,
                this.keyRingId,
                this.keyId
            );
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

    async encryptDEK(dek) {
        try {
            if (this.isDevelopment) {
                // Local encryption for development
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
            console.log("Encrypting with KMS key:", this.keyName);
            const [encryptResponse] = await this.client.encrypt({
                name: this.keyName,
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

    async decryptDEK(encryptedDEKData) {
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

            // Production: use Google Cloud KMS
            console.log("Decrypting with KMS key:", this.keyName);
            const [decryptResponse] = await this.client.decrypt({
                name: this.keyName,
                ciphertext: encryptedDEKData.encryptedDEK
            });

            return Buffer.from(decryptResponse.plaintext, 'base64');
        } catch (error) {
            console.error('Error decrypting DEK:', error);
            throw new Error('Failed to decrypt DEK');
        }
    }
}

module.exports = new KMSService(); 