import { SecretManagerServiceClient } from '@google-cloud/secret-manager';

interface SecretVersion {
    secretName: string;
    versionName: string;
}

class SecretManagerService {
    private secretManager: SecretManagerServiceClient;
    private cache: Map<string, Buffer>;

    constructor() {
        this.secretManager = new SecretManagerServiceClient();
        // Initialize cache
        this.cache = new Map();
    }

    async createSecret(secretId: string, encryptedDEK: Buffer): Promise<SecretVersion> {
        try {
            // Create the secret
            const [secret] = await this.secretManager.createSecret({
                parent: `projects/${process.env.GOOGLE_CLOUD_PROJECT}`,
                secretId: secretId,
                secret: {
                    replication: {
                        automatic: {},
                    },
                },
            });
            console.log("🚀 ~ SecretManagerService ~ createSecret ~ secret:", secret)

            // Add the encrypted DEK as a version

            const [version] = await this.secretManager.addSecretVersion({
                parent: secret.name,
                payload: {
                    data: encryptedDEK,
                },
            });
            console.log("🚀 ~ SecretManagerService ~ createSecret ~ version:", version)

            // Cache the encrypted DEK
            this.cache.set(secretId, encryptedDEK);
            console.log("ENCRYPTED DEK>>>>>>>>>>>>", encryptedDEK.toString('base64'), "<<<<<<<<<<<<<<<<ENCRYPTED DEK")
            return {
                secretName: secret.name || '',
                versionName: version.name || ''
            };
        } catch (error) {
            console.error('Error creating secret:', error);
            throw error;
        }
    }

    async getSecret(secretName: string): Promise<Buffer> {
        try {
            // Check if secret is in cache
            // if (this.cache.has(secretName)) {
            //     return this.cache.get(secretName)!;
            // }
            console.log('SECRET KEY NOT FOUND IN CACHE')
            const secretVersionName = `projects/${process.env.GOOGLE_CLOUD_PROJECT}/secrets/${secretName}/versions/latest`;

            const [version] = await this.secretManager.accessSecretVersion({
                name: secretVersionName,
            });
            const encryptedDEK = version.payload?.data;
            console.log("ENCRYPTED DEK>>>>>>>>>>>>", encryptedDEK ? Buffer.from(encryptedDEK).toString('base64') : 'undefined', "<<<<<<<<<<<<<<<<ENCRYPTED DEK")
            console.log('RETRIEVED SECRET KEY')
            // Cache the encrypted DEK
            console.log('CACHED SECRET KEY')
            if (!encryptedDEK) {
                throw new Error(`No payload data found in secret version for ${secretName}`);
            }
            const encryptedDEKBuffer = Buffer.from(encryptedDEK);
            this.cache.set(secretName, encryptedDEKBuffer);

            return encryptedDEKBuffer;
        } catch (error) {
            console.error('Error accessing secret:', error);
            throw error;
        }
    }

    // Method to clear cache if needed
    clearCache(): void {
        this.cache.clear();
    }

    // Method to remove specific secret from cache
    removeFromCache(secretName: string): void {
        this.cache.delete(secretName);
    }
}

export default new SecretManagerService(); 