// Export services
export { default as KMSService } from './services/kmsService';
export { default as SecretManagerService } from './services/secretManagerService';
export { default as EncryptionService } from './services/encryptionService';

// Export types
export type { KeyMetadata } from './services/kmsService';
export type { SecretVersion, SecretData } from './services/secretManagerService';
export type { EntityKeyDetails, EntityKeyDetailsResult } from './types/encryption';

// Export interfaces
export interface EncryptionConfig {
    encryptedFields: {
        [key: string]: {
            shouldHash: boolean;
        };
    };
}

