import { SecretManagerServiceClient } from '@google-cloud/secret-manager';
import {
    ConfigurationError,
    EncryptionError,
    ValidationError,
    ErrorCodes
} from '../types/errors';

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
    keyVersion: string;
}

/**
 * Service for managing secrets in Google Cloud Secret Manager
 */
class SecretManagerService {
    private readonly secretManager: SecretManagerServiceClient;
    private readonly projectId: string;

    constructor() {
        try {
            this.secretManager = new SecretManagerServiceClient();
            this.projectId = process.env.GOOGLE_CLOUD_PROJECT || '';

            if (!this.projectId) {
                throw new ConfigurationError(
                    'GOOGLE_CLOUD_PROJECT environment variable is required',
                    ErrorCodes.CONFIGURATION.MISSING_ENV_VAR
                );
            }
        } catch (error) {
            if (error instanceof ConfigurationError) {
                throw error;
            }
            throw new ConfigurationError(
                `Failed to initialize Secret Manager service: ${error instanceof Error ? error.message : 'Unknown error'}`,
                ErrorCodes.CONFIGURATION.INITIALIZATION_ERROR
            );
        }
    }

    /**
     * Creates a new secret and adds the encrypted DEK as a version
     * @param secretId - Unique identifier for the secret
     * @param secretData - Data to be stored in the secret
     * @returns Promise resolving to the created secret version
     * @throws {ValidationError} When required parameters are missing
     * @throws {EncryptionError} When secret creation fails
     */
    async createSecret(secretId: string, secretData: SecretData): Promise<SecretVersion> {
        try {
            if (!secretId) {
                throw new ValidationError(
                    'Secret ID is required',
                    ErrorCodes.VALIDATION.MISSING_REQUIRED_FIELD
                );
            }

            if (!secretData.encryptedDEK) {
                throw new ValidationError(
                    'Encrypted DEK is required',
                    ErrorCodes.VALIDATION.MISSING_REQUIRED_FIELD
                );
            }

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
                throw new EncryptionError(
                    'Failed to create secret: No name returned',
                    ErrorCodes.ENCRYPTION.CREATION_ERROR
                );
            }

            // Add the encrypted DEK as a version
            const [version] = await this.secretManager.addSecretVersion({
                parent: secret.name,
                payload: {
                    data: secretData.encryptedDEK,
                },
            });

            if (!version.name) {
                throw new EncryptionError(
                    'Failed to create secret version: No name returned',
                    ErrorCodes.ENCRYPTION.CREATION_ERROR
                );
            }

            return {
                secretName: secret.name,
                versionName: version.name
            };
        } catch (error) {
            if (error instanceof ValidationError || error instanceof EncryptionError) {
                throw error;
            }
            throw new EncryptionError(
                `Failed to create secret: ${error instanceof Error ? error.message : 'Unknown error'}`,
                ErrorCodes.ENCRYPTION.CREATION_ERROR
            );
        }
    }

    /**
     * Retrieves the latest version of a secret
     * @param secretName - Name of the secret to retrieve
     * @returns Promise resolving to the secret data as a Buffer
     * @throws {ValidationError} When secret name is missing
     * @throws {EncryptionError} When secret retrieval fails
     */
    async getSecret(secretName: string): Promise<Buffer> {
        try {
            if (!secretName) {
                throw new ValidationError(
                    'Secret name is required',
                    ErrorCodes.VALIDATION.MISSING_REQUIRED_FIELD
                );
            }

            const secretVersionName = `projects/${this.projectId}/secrets/${secretName}/versions/latest`;

            const [version] = await this.secretManager.accessSecretVersion({
                name: secretVersionName,
            });

            const encryptedDEK = version.payload?.data;
            if (!encryptedDEK) {
                throw new EncryptionError(
                    `No payload data found in secret version for ${secretName}`,
                    ErrorCodes.ENCRYPTION.SECRET_RETRIEVAL_ERROR
                );
            }

            return Buffer.from(encryptedDEK);
        } catch (error) {
            if (error instanceof ValidationError || error instanceof EncryptionError) {
                throw error;
            }
            throw new EncryptionError(
                `Failed to access secret: ${error instanceof Error ? error.message : 'Unknown error'}`,
                ErrorCodes.ENCRYPTION.SECRET_RETRIEVAL_ERROR
            );
        }
    }
}

export default new SecretManagerService(); 