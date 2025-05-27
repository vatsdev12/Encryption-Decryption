export interface EncryptionConfig {
    encryptedFields: {
        [key: string]: {
            Encrypt: {
                key: string;
                shouldHash: boolean;
            }[];
            Decrypt: {
                key: string;
                shouldHash: boolean;
            }[];
        };
    };
}

export interface KeyMetadata {
    locationId: string;
    keyRingId: string;
    keyId: string;
    secretId: string;
    encryptedDEK?: Buffer | null;
    keyVersion: string | null;
}

export interface EncryptedFieldData {
    [key: string]: string;
}

export interface EncryptedObjectResult {
    encryptedData: any;
}
export interface KeyDetailsObjectResult {
    kmsPath: string;
    secretId: string;
    secretNamePath: string;
    encryptedDEK: Buffer;
}

export interface EntityKeyDetails {
    locationId: string | null;
    keyRingId: string | null;
    keyId: string | null;
    secretId: string | null;
    encryptedDEK?: Buffer | null;
    keyVersion: string | null;
}

export interface EntityKeyDetailsResult {
    kmsPath: string;
    secretId: string;
    secretNamePath: string;
    encryptedDEK?: Buffer;
}
export interface EncryptObjectParams {
    modelName: string;
    data: any;
    entityKeyDetailsResult: EntityKeyDetailsResult;
}
