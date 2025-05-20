const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');

class SecretManagerService {
    constructor() {
        this.secretManager = new SecretManagerServiceClient();
        // Initialize cache
        this.cache = new Map();
    }

    async createSecret(secretId, encryptedDEK) {
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

            // Add the encrypted DEK as a version
            const [version] = await this.secretManager.addSecretVersion({
                parent: secret.name,
                payload: {
                    data: encryptedDEK.toString('base64'),
                },
            });

            // Cache the encrypted DEK
            this.cache.set(secretId, encryptedDEK);

            return {
                secretName: secret.name,
                versionName: version.name
            };
        } catch (error) {
            console.error('Error creating secret:', error);
            throw error;
        }
    }

    async getSecret(secretName) {
        console.log("🚀 ~ SecretManagerService ~ getSecret ~ secretName:", secretName);

        // Check if secret is in cache
        if (this.cache.has(secretName)) {
            console.log("Cache hit for secret:", secretName);
            return this.cache.get(secretName);
        }

        const secretVersionName = `projects/${process.env.GOOGLE_CLOUD_PROJECT}/secrets/${secretName}/versions/latest`;
        try {
            const [version] = await this.secretManager.accessSecretVersion({
                name: secretVersionName,
            });
            const encryptedDEK = Buffer.from(version.payload.data, 'base64');

            // Cache the encrypted DEK
            this.cache.set(secretName, encryptedDEK);
            console.log("Cached secret:", secretName);

            return encryptedDEK;
        } catch (error) {
            console.error('Error accessing secret:', error);
            throw error;
        }
    }

    // Method to clear cache if needed
    clearCache() {
        this.cache.clear();
    }

    // Method to remove specific secret from cache
    removeFromCache(secretName) {
        this.cache.delete(secretName);
    }
}

module.exports = new SecretManagerService(); 