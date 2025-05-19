const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const ClientKey = sequelize.define('ClientKey', {
    client_id: {
        type: DataTypes.UUID,
        allowNull: false,
        primaryKey: true
    },
    key_version: {
        type: DataTypes.INTEGER,
        allowNull: false,
        primaryKey: true
    },
    secret_key: {
        type: DataTypes.STRING,
        allowNull: false
    },
    created_at: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW
    },
    active: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
    }
}, {
    tableName: 'client_keys',
    timestamps: false
});

module.exports = ClientKey; 