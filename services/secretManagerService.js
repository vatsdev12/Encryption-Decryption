const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
const NodeCache = require('node-cache');

class SecretManagerService {
    constructor() {
        this.client = new SecretManagerServiceClient();
        this.projectId = process.env.GOOGLE_CLOUD_PROJECT;
        this.cache = new NodeCache({ stdTTL: 1800 }); // 30 minutes cache
    }

    async getSecret(secretId) {
        const cacheKey = `secret_${secretId}`;

        // Try to get from cache first
        const cachedSecret = this.cache.get(cacheKey);
        if (cachedSecret) {
            return cachedSecret;
        }

        // If not in cache, fetch from Secret Manager
        const name = `projects/${this.projectId}/secrets/${secretId}/versions/latest`;
        try {
            const [version] = await this.client.accessSecretVersion({ name });
            const secretValue = version.payload.data.toString();

            // Store in cache
            this.cache.set(cacheKey, secretValue);

            return secretValue;
        } catch (error) {
            console.error(`Error accessing secret ${secretId}:`, error);
            throw new Error(`Failed to access secret ${secretId}`);
        }
    }

    async createSecret(secretId, secretValue) {
        console.log("🚀 ~ SecretManagerService ~ createSecret ~ secretId, secretValue:", secretId, secretValue)
        const parent = `projects/${this.projectId}`;

        try {
            // Create the secret
            const [secret] = await this.client.createSecret({
                parent,
                secretId,
                secret: {
                    replication: {
                        automatic: {},
                    },
                },
            });

            // Add the secret version
            const [version] = await this.client.addSecretVersion({
                parent: secret.name,
                payload: {
                    data: Buffer.from(secretValue),
                },
            });

            return version;
        } catch (error) {
            console.error(`Error creating secret ${secretId}:`, error);
            throw new Error(`Failed to create secret ${secretId}`);
        }
    }

    async deleteSecret(secretId) {
        const name = `projects/${this.projectId}/secrets/${secretId}`;
        try {
            await this.client.deleteSecret({ name });
            // Remove from cache if exists
            this.cache.del(`secret_${secretId}`);
        } catch (error) {
            console.error(`Error deleting secret ${secretId}:`, error);
            throw new Error(`Failed to delete secret ${secretId}`);
        }
    }
}

module.exports = new SecretManagerService(); 