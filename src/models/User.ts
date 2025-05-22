import { Model, DataTypes } from 'sequelize';
import sequelize from '../config/database';
import UserKeyDetails from './UserKeyDetails';
import { checkKMS } from '../utils/checkkms';
import cacheService from '../services/cacheService';
import { UserAttributes, UserCreationAttributes, KeyMetadata } from '../types/encryption';
import { EncryptionService, EntityKeyDetailsResult } from '@vatsdev/encryption-decryption-poc';




class User extends Model<UserAttributes, UserCreationAttributes> implements UserAttributes {
    public id!: number;
    public username!: string;
    public email!: string;
    public email_encrypted!: string;
    public email_iv?: string;
    public email_dek?: string;
    public email_auth_tag?: string;
    public email_hash?: string;
    public password!: string;
    public password_encrypted!: string;
    public password_iv?: string;
    public password_dek?: string;
    public password_auth_tag?: string;
    public firstName?: string;
    public firstName_encrypted!: string;
    public firstName_iv?: string;
    public firstName_dek?: string;
    public firstName_auth_tag?: string;
    public lastName?: string;
    public lastName_encrypted!: string;
    public lastName_iv?: string;
    public lastName_dek?: string;
    public lastName_auth_tag?: string;
    public isActive!: boolean;
    public readonly createdAt!: Date;
    public readonly updatedAt!: Date;
    public _keyMetadata?: KeyMetadata;
    public _isCached?: boolean;
}

User.init({
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    username: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    email: {
        type: DataTypes.TEXT,
        allowNull: false,
        unique: true
    },
    email_encrypted: {
        type: DataTypes.TEXT,
        defaultValue: false
    },
    email_iv: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    email_dek: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    email_auth_tag: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    email_hash: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    password: {
        type: DataTypes.TEXT,
        allowNull: false
    },
    password_encrypted: {
        type: DataTypes.TEXT,
        defaultValue: 'false'
    },
    password_iv: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    password_dek: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    password_auth_tag: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    firstName: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    firstName_encrypted: {
        type: DataTypes.TEXT,
        defaultValue: 'false'
    },
    firstName_iv: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    firstName_dek: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    firstName_auth_tag: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    lastName: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    lastName_encrypted: {
        type: DataTypes.TEXT,
        defaultValue: 'false'
    },
    lastName_iv: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    lastName_dek: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    lastName_auth_tag: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
    }
}, {
    sequelize,
    timestamps: true,
    tableName: 'Users',
    hooks: {
        beforeCreate: async (user: User) => {
            //fetch UserKeyDetails from UserKeyDetails table for the user
            const userKeyDetails = await checkKMS(user.dataValues.username, 22);
            const entityKeyDetails: EntityKeyDetailsResult = {
                keyDetails: userKeyDetails.userKeyDetails,
                isCached: userKeyDetails.isCached,
                isEntityKeyDetails: userKeyDetails.isUserKeyDetails
            };
            const { encryptedData, keyMetadata } = await EncryptionService.encryptObject('User', user.dataValues, user.dataValues.username, entityKeyDetails);
            Object.assign(user, encryptedData);

            //cache the keyMetadata
            const secretId = `secret-${user.dataValues.username}`;
            cacheService.set(secretId, keyMetadata);
            //check if cache is set
            const cachedData = cacheService.get(secretId);

            user._keyMetadata = keyMetadata;
        },
        // beforeUpdate: async (user: User) => {
        //     const { encryptedData } = await encryptionService.encryptObject('User', user.dataValues);
        //     Object.assign(user, encryptedData);
        // },
        afterCreate: async (user: User) => {
            const metadata = user._keyMetadata;
            console.log("🚀 ~ afterCreate: ~ metadata:", metadata)

            if (metadata) {
                await UserKeyDetails.create({
                    userId: user.id,
                    locationId: metadata.locationId,
                    keyRingId: metadata.keyRingId,
                    keyId: metadata.keyId,
                    secretId: metadata.secretId
                });
            }
        },
        afterFind: async (result: User | User[] | null) => {
            if (Array.isArray(result)) {
                for (const user of result) {
                    //fetch UserKeyDetails from UserKeyDetails table for the user
                    const userKeyDetail = await checkKMS(user.dataValues.username, user.dataValues.id);
                    const entityKeyDetails: EntityKeyDetailsResult = {
                        keyDetails: userKeyDetail.userKeyDetails,
                        isCached: userKeyDetail.isCached,
                        isEntityKeyDetails: userKeyDetail.isUserKeyDetails
                    };
                    const { decryptedData, encryptedDEK } = await EncryptionService.decryptObject('User', user.dataValues, entityKeyDetails);

                    console.log("🚀 ~ afterFind: ~ decryptedData:", decryptedData)
                    console.log("🚀 ~ afterFind: ~ encryptedDEK:", encryptedDEK)
                    //cache the encryptedDEK
                    //if encryptedDEK has value then only update the value of encryptedDEK in the cache otherwise cache the userKeyDetails

                    if (encryptedDEK) {
                        const userKeyDetails = { ...userKeyDetail.userKeyDetails, encryptedDEK };
                        const secretId = `secret-${user.dataValues.username}`;
                        cacheService.set(secretId, userKeyDetails);
                        //check if cache is set
                        const cachedData = cacheService.get(secretId);
                        console.log("🚀 ~ afterFind: ~ cachedData:", cachedData)
                    }
                    else {
                        const secretId = `secret-${user.dataValues.username}`;
                        cacheService.set(secretId, userKeyDetail.userKeyDetails);
                        //check if cache is set
                        const cachedData = cacheService.get(secretId);
                        console.log("🚀 ~ afterFind: ~ cachedData:", cachedData)
                    }

                    Object.assign(user, decryptedData);
                }
            } else if (result) {
                const decryptedData = await EncryptionService.decryptObject('User', result.dataValues);
                Object.assign(result, decryptedData);
            }
        }
    }
});

export default User; 