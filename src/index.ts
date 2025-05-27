// Export all utility functions
export {
    generateDEK,
    encryptField,
    decryptField,
    handleFieldEncryption,
    createNewEncryption,
    createHash
} from './utils';

// Export services
export { default as EncryptionService } from './services/encryptionService';
export { default as kmsService } from './services/kmsService';
export { default as secretManagerService } from './services/secretManagerService';

// Export types
export * from './types/encryption';
export * from './types/errors';

// Export interfaces
export interface EncryptionConfig {
    encryptedFields: {
        [key: string]: {
            shouldHash: boolean;
        };
    };
}

