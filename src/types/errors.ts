export class ConfigurationError extends Error {
    constructor(message: string, public code: string) {
        super(message);
        this.name = 'ConfigurationError';
    }
}

export class EncryptionError extends Error {
    constructor(message: string, public code: string) {
        super(message);
        this.name = 'EncryptionError';
    }
}

export class ValidationError extends Error {
    constructor(message: string, public code: string) {
        super(message);
        this.name = 'ValidationError';
    }
}

export const ErrorCodes = {
    CONFIGURATION: {
        MISSING_CONFIG: 'CONFIGURATION_MISSING_CONFIG',
        MISSING_ENV_VAR: 'CONFIGURATION_MISSING_ENV_VAR',
        INITIALIZATION_ERROR: 'CONFIGURATION_INITIALIZATION_ERROR'
    },
    ENCRYPTION: {
        FIELD_ENCRYPTION_ERROR: 'ENCRYPTION_FIELD_ENCRYPTION_ERROR',
        FIELD_DECRYPTION_ERROR: 'ENCRYPTION_FIELD_DECRYPTION_ERROR',
        DEK_RESOLUTION_ERROR: 'ENCRYPTION_DEK_RESOLUTION_ERROR',
        DEK_DECRYPTION_ERROR: 'ENCRYPTION_DEK_DECRYPTION_ERROR',
        DEK_ENCRYPTION_ERROR: 'ENCRYPTION_DEK_ENCRYPTION_ERROR',
        SECRET_RETRIEVAL_ERROR: 'ENCRYPTION_SECRET_RETRIEVAL_ERROR',
        UNKNOWN_ERROR: 'ENCRYPTION_UNKNOWN_ERROR',
        KEY_DETAILS_ERROR: 'ENCRYPTION_KEY_DETAILS_ERROR',
        KEY_VERSION_ERROR: 'ENCRYPTION_KEY_VERSION_ERROR',
        KEY_CREATION_ERROR: 'ENCRYPTION_KEY_CREATION_ERROR',
        CREATION_ERROR: 'ENCRYPTION_CREATION_ERROR'
    },
    VALIDATION: {
        MISSING_REQUIRED_FIELD: 'VALIDATION_MISSING_REQUIRED_FIELD',
        INVALID_DEK: 'VALIDATION_INVALID_DEK'
    }
};