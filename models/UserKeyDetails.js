const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');
const encryptionService = require('../services/encryptionService');

const UserKeyDetails = sequelize.define('UserKeyDetails', {
    locationId: {
        type: DataTypes.STRING,
        allowNull: false
    },
    keyRingId: {
        type: DataTypes.STRING,
        allowNull: false
    },
    keyId: {
        type: DataTypes.STRING,
        allowNull: false
    },
    secretId: {
        type: DataTypes.STRING,
        allowNull: false
    },
    userId: {
        type: DataTypes.INTEGER,
        allowNull: false
    }
}, {
    timestamps: true,
    tableName: 'UserKeyDetails', 
});

module.exports = UserKeyDetails; 