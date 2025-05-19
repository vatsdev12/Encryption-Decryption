'use strict';

module.exports = {
    up: async (queryInterface, Sequelize) => {
        await queryInterface.createTable('client_keys', {
            client_id: {
                type: Sequelize.UUID,
                allowNull: false,
                primaryKey: true
            },
            key_version: {
                type: Sequelize.INTEGER,
                allowNull: false,
                primaryKey: true
            },
            key_encrypted: {
                type: Sequelize.BLOB,
                allowNull: false
            },
            created_at: {
                type: Sequelize.DATE,
                defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
            },
            active: {
                type: Sequelize.BOOLEAN,
                defaultValue: true
            }
        });

        // Add indexes
        await queryInterface.addIndex('client_keys', ['client_id', 'active']);
    },

    down: async (queryInterface, Sequelize) => {
        await queryInterface.dropTable('client_keys');
    }
}; 