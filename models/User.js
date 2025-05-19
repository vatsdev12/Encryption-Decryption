const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');
const encryptionService = require('../services/encryptionService');
const crypto = require('crypto');

const User = sequelize.define('User', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    },
    username: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    email: {
        type: DataTypes.TEXT,
        allowNull: false
    },
    email_hash: {
        type: DataTypes.STRING(64), // SHA-256 hash is 64 characters
        allowNull: false,
        unique: true
    },
    password: {
        type: DataTypes.TEXT,
        allowNull: false
    },
    firstName: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    lastName: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
    },
    // Encryption metadata fields
    email_iv: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    email_auth_tag: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    password_iv: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    password_auth_tag: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    firstName_iv: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    firstName_auth_tag: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    lastName_iv: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    lastName_auth_tag: {
        type: DataTypes.TEXT,
        allowNull: true
    }
}, {
    timestamps: true,
    tableName: 'Users',
    hooks: {
        beforeValidate: async (user) => {
            // Generate email hash before validation
            if (user.email) {
                user.email_hash = crypto.createHash('sha256')
                    .update(user.email.toLowerCase())
                    .digest('hex');
            }
        },
        beforeCreate: async (user) => {
            // Encrypt sensitive fields
            const encryptedData = await encryptionService.encryptObject('User', user.toJSON());
            Object.assign(user, encryptedData);
        },
        beforeUpdate: async (user) => {
            // If email is being updated, update the hash
            if (user.changed('email')) {
                user.email_hash = crypto.createHash('sha256')
                    .update(user.email.toLowerCase())
                    .digest('hex');
            }

            // Only encrypt changed fields
            const changes = user.changed();
            if (changes.length > 0) {
                const dataToEncrypt = {};
                changes.forEach(field => {
                    if (['email', 'password', 'firstName', 'lastName'].includes(field)) {
                        dataToEncrypt[field] = user[field];
                    }
                });

                if (Object.keys(dataToEncrypt).length > 0) {
                    const encryptedData = await encryptionService.encryptObject('User', {
                        ...dataToEncrypt,
                        id: user.id
                    });
                    Object.assign(user, encryptedData);
                }
            }
        },
        afterFind: async (user) => {
            if (!user) return;

            // Decrypt sensitive fields
            const decryptedData = await encryptionService.decryptObject('User', user.toJSON());
            Object.assign(user, decryptedData);
        }
    }
});

module.exports = User; 