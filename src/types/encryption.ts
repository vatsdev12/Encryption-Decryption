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
}

export interface EncryptedFieldData {
    [key: string]: string;
}

export interface EncryptedObjectResult {
    encryptedData: any;
    keyMetadata: KeyMetadata;
}

export interface EntityKeyDetails {
    locationId: string | null;
    keyRingId: string | null;
    keyId: string | null;
    secretId: string | null;
    encryptedDEK?: Buffer | null;
}

export interface EntityKeyDetailsResult {
    keyDetails: EntityKeyDetails;
    isCached: boolean;
    isEntityKeyDetails: boolean;
}