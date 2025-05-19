const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');
const encryptionService = require('../services/encryptionService');

const User = sequelize.define('User', {
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
    password: {
        type: DataTypes.TEXT,
        allowNull: false
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
    },
    firstName_secret_id: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    lastName_secret_id: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    email_secret_id: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    password_secret_id: {
        type: DataTypes.TEXT,
        allowNull: true
    }
}, {
    timestamps: true,
    tableName: 'Users', // Explicitly set table name
    hooks: {
        beforeCreate: async (user) => {
            const encryptedData = await encryptionService.encryptObject('User', user.dataValues);
            Object.assign(user, encryptedData);
        },
        beforeUpdate: async (user) => {
            const encryptedData = await encryptionService.encryptObject('User', user.dataValues);
            Object.assign(user, encryptedData);
        },
        afterFind: async (result) => {
            if (Array.isArray(result)) {
                for (const user of result) {
                    const decryptedData = await encryptionService.decryptObject('User', user.dataValues);
                    Object.assign(user, decryptedData);
                }
            } else if (result) {
                const decryptedData = await encryptionService.decryptObject('User', result.dataValues);
                Object.assign(result, decryptedData);
            }
        }


    }
});

module.exports = User; 