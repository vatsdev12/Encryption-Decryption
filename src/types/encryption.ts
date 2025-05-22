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

export interface UserKeyDetails {
    locationId: string | null;
    keyRingId: string | null;
    keyId: string | null;
    secretId: string | null;
    encryptedDEK?: Buffer | null;
}

export interface UserKeyDetailsResult {
    userKeyDetails: UserKeyDetails;
    isCached: boolean;
    isUserKeyDetails: boolean;
}

export interface UserAttributes {
    id: number;
    username: string;
    email: string;
    email_iv?: string;
    email_dek?: string;
    email_auth_tag?: string;
    email_hash?: string;
    password: string;
    password_iv?: string;
    password_dek?: string;
    password_auth_tag?: string;
    firstName?: string;
    firstName_iv?: string;
    firstName_dek?: string;
    firstName_auth_tag?: string;
    lastName?: string;
    lastName_iv?: string;
    lastName_dek?: string;
    lastName_auth_tag?: string;
    isActive: boolean;
    createdAt?: Date;
    updatedAt?: Date;
}

export interface UserCreationAttributes extends Omit<UserAttributes, 'id'> { } 