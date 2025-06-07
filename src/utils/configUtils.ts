import fs from 'fs';
import path from 'path';
import { ConfigurationError, ErrorCodes } from '../types/errors';
import { EncryptionConfig } from '../types/encryption';

let configCache: EncryptionConfig | null = null;

/**
 * Reads and caches the encryption configuration
 * @returns Encryption configuration object
 * @throws {ConfigurationError} When configuration file is missing or invalid
 */
export const getEncryptionConfig = (): EncryptionConfig => {
    if (configCache) {
        return configCache;
    }

    try {
        const configPath = process.env.CONFIG_PATH || path.join(process.cwd(), 'config/encryption.json');
        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        configCache = config;
        return config;
    } catch (error) {
        throw new ConfigurationError(
            `Failed to read encryption configuration: ${error instanceof Error ? error.message : 'Unknown error'}`,
            ErrorCodes.CONFIGURATION.MISSING_CONFIG
        );
    }
};

/**
 * Gets the encryption configuration for a specific model
 * @param modelName - Name of the model to get configuration for
 * @returns Model-specific encryption configuration
 * @throws {ConfigurationError} When model configuration is not found
 */
export const getModelConfig = (modelName: string) => {
    const config = getEncryptionConfig();
    const modelConfig = config[modelName];

    if (!modelConfig) {
        throw new ConfigurationError(
            `Encryption configuration not found for model ${modelName}`,
            ErrorCodes.CONFIGURATION.MISSING_CONFIG
        );
    }

    return modelConfig;
}; 