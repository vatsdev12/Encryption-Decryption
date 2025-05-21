import { KeyManagementServiceClient } from '@google-cloud/kms';
import crypto from 'crypto';
import createKms from '../utils/createKms';

interface KeyMetadata {
    locationId: string;
    keyRingId: string;
    keyId: string;
}

interface EncryptDEKResult {
    encryptedDEK: Buffer;
    locationId: string;
    keyRingId: string;
    keyId: string;
}

interface DecryptDEKParams {
    encryptedDEKData: Buffer;
    keyMetadata: KeyMetadata;
}

class KMSService {
    private client!: KeyManagementServiceClient;
    private projectId!: string;
    private locationId!: string;
    private localKey!: Buffer;

    constructor() {
        this.client = new KeyManagementServiceClient();
        this.projectId = process.env.GOOGLE_CLOUD_PROJECT || '';
        this.locationId = process.env.KMS_LOCATION_ID || 'global';
    }


    async createKeyRingAndKey(dek: Buffer, kmsKeyName?: string): Promise<EncryptDEKResult> {
        console.log('CREATING KEY RING AND KEY')
        const { keyRingId, keyId } = createKms(kmsKeyName || Math.random().toString(36).substring(2, 15));

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

        // Encrypt the DEK - send raw buffer
        const [encryptResponse] = await this.client.encrypt({
            name: key.name,
            plaintext: dek
        });

        return {
            encryptedDEK: encryptResponse.ciphertext as Buffer,
            locationId: this.locationId,
            keyRingId: keyRingId,
            keyId: keyId
        };
    }

    async encryptDEK(dek: Buffer, kmsKeyName?: string): Promise<EncryptDEKResult> {
        try {
            //create a new locationId , keyRingId , keyId in the gcp kms
            const { encryptedDEK, locationId, keyRingId, keyId } = await this.createKeyRingAndKey(dek, kmsKeyName);

            return {
                encryptedDEK,
                locationId: this.locationId,
                keyRingId: keyRingId,
                keyId: keyId,
            };
        } catch (error) {
            console.error('Error encrypting DEK:', error);
            throw new Error('Failed to encrypt DEK');
        }
    }

    async decryptDEK({ encryptedDEKData, keyMetadata }: DecryptDEKParams): Promise<Buffer> {
        try {
            console.log('DECRYPTING THE DEK')
            const keyName = this.client.cryptoKeyPath(
                this.projectId,
                keyMetadata.locationId,
                keyMetadata.keyRingId,
                keyMetadata.keyId
            );
            console.log('KEY NAME CREATED')

            const [decryptResponse] = await this.client.decrypt({
                name: keyName,
                ciphertext: encryptedDEKData
            });
            console.log('DECRYPT RESPONSE', decryptResponse)

            // The plaintext is already a Buffer
            const dek = decryptResponse.plaintext as Buffer;

            // Ensure we have a 32-byte key for AES-256-GCM
            if (dek.length !== 32) {
                throw new Error(`Invalid DEK length: ${dek.length} bytes. Expected 32 bytes for AES-256-GCM`);
            }

            return dek;
        } catch (error) {
            console.error('Error decrypting DEK:', error);
            throw new Error('Failed to decrypt DEK');
        }
    }
}

export default new KMSService(); 