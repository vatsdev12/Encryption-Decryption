import { SecretManagerServiceClient } from '@google-cloud/secret-manager';

/**
 * Represents a secret version in Google Cloud Secret Manager
 */
export interface SecretVersion {
    secretName: string;
    versionName: string;
}

/**
 * Data structure for storing encrypted DEK and its metadata
 */
export interface SecretData {
    encryptedDEK: Buffer;
    locationId: string;
    keyRingId: string;
    keyId: string;
}

/**
 * Service for managing secrets in Google Cloud Secret Manager
 */
class SecretManagerService {
    private readonly secretManager: SecretManagerServiceClient;
    private readonly projectId: string;

    constructor() {
        this.secretManager = new SecretManagerServiceClient();
        this.projectId = process.env.GOOGLE_CLOUD_PROJECT || '';

        if (!this.projectId) {
            throw new Error('GOOGLE_CLOUD_PROJECT environment variable is required');
        }
    }

    /**
     * Creates a new secret and adds the encrypted DEK as a version
     * @param secretId - Unique identifier for the secret
     * @param secretData - Data to be stored in the secret
     * @returns Promise resolving to the created secret version
     */
    async createSecret(secretId: string, secretData: SecretData): Promise<SecretVersion> {
        try {
            const parent = `projects/${this.projectId}`;

            // Create the secret
            const [secret] = await this.secretManager.createSecret({
                parent,
                secretId,
                secret: {
                    replication: {
                        automatic: {},
                    },
                },
            });

            if (!secret.name) {
                throw new Error('Failed to create secret: No name returned');
            }

            // Add the encrypted DEK as a version
            const [version] = await this.secretManager.addSecretVersion({
                parent: secret.name,
                payload: {
                    data: secretData.encryptedDEK,
                },
            });

            if (!version.name) {
                throw new Error('Failed to create secret version: No name returned');
            }

            return {
                secretName: secret.name,
                versionName: version.name
            };
        } catch (error) {
            throw new Error(`Failed to create secret: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Retrieves the latest version of a secret
     * @param secretName - Name of the secret to retrieve
     * @returns Promise resolving to the secret data as a Buffer
     */
    async getSecret(secretName: string): Promise<Buffer> {
        try {
            const secretVersionName = `projects/${this.projectId}/secrets/${secretName}/versions/latest`;

            const [version] = await this.secretManager.accessSecretVersion({
                name: secretVersionName,
            });

            const encryptedDEK = version.payload?.data;
            if (!encryptedDEK) {
                throw new Error(`No payload data found in secret version for ${secretName}`);
            }

            return Buffer.from(encryptedDEK);
        } catch (error) {
            throw new Error(`Failed to access secret: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
}

export default new SecretManagerService(); 