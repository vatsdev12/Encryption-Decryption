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

    async createKeyRingAndKey(dek, username) {
        const keyRingId = `kr-${username}-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        const keyId = `key-${username}-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

        const locationName = this.client.locationPath(this.projectId, this.locationId);

        // Create KeyRing
        await this.client.createKeyRing({
            parent: locationName,
            keyRingId: keyRingId,
            keyRing: {}
        });

        console.log(`✅ Created KeyRing: ${keyRingId}`);

        // Create CryptoKey
        const [key] = await this.client.createCryptoKey({
            parent: this.client.keyRingPath(this.projectId, this.locationId, keyRingId),
            cryptoKeyId: keyId,
            cryptoKey: {
                purpose: 'ENCRYPT_DECRYPT',
                versionTemplate: {
                    algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION',
                },
            }
        });

        console.log(`✅ Created CryptoKey: ${keyId}`);

        const [encryptResponse] = await this.client.encrypt({
            name: key.name,
            plaintext: dek.toString('base64')
        });

        const encryptedDEK = encryptResponse.ciphertext;

        return {
            encryptedDEK,
            locationId: this.locationId,
            keyRingId: keyRingId,
            keyId: keyId,
            username: username
        };
    }

    async encryptDEK(dek, username) {
        try {
            //create a new locationId , keyRingId , keyId in the gcp kms
            const { encryptedDEK, locationId, keyRingId, keyId } = await this.createKeyRingAndKey(dek, username);

            return {
                encryptedDEK: encryptedDEK,
                locationId: this.locationId,
                keyRingId: keyRingId,
                keyId: keyId,
            };
        } catch (error) {
            console.error('Error encrypting DEK:', error);
            throw new Error('Failed to encrypt DEK');
        }
    }

    async decryptDEK({ encryptedDEKData, keyMetadata }) {
        try {
            const keyName = this.client.cryptoKeyPath(
                this.projectId,
                keyMetadata.locationId,
                keyMetadata.keyRingId,
                keyMetadata.keyId
            );
            // Production: use Google Cloud KMS
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