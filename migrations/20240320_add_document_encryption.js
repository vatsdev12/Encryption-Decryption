'use strict';

module.exports = {
    up: async (queryInterface, Sequelize) => {
        // Add document-level encryption fields
        await queryInterface.addColumn('Users', 'document_iv', {
            type: Sequelize.TEXT,
            allowNull: true
        });
        await queryInterface.addColumn('Users', 'document_secret_id', {
            type: Sequelize.TEXT,
            allowNull: true
        });
        await queryInterface.addColumn('Users', 'document_auth_tag', {
            type: Sequelize.TEXT,
            allowNull: true
        });
        await queryInterface.addColumn('Users', 'key_version', {
            type: Sequelize.INTEGER,
            allowNull: true,
            defaultValue: 1
        });

        // Remove field-level encryption metadata
        const fields = ['email', 'password', 'firstName', 'lastName'];
        for (const field of fields) {
            await queryInterface.removeColumn('Users', `${field}_iv`);
            await queryInterface.removeColumn('Users', `${field}_secret_id`);
            await queryInterface.removeColumn('Users', `${field}_auth_tag`);
            await queryInterface.removeColumn('Users', `${field}_dek`);
        }
    },

    down: async (queryInterface, Sequelize) => {
        // Remove document-level encryption fields
        await queryInterface.removeColumn('Users', 'document_iv');
        await queryInterface.removeColumn('Users', 'document_secret_id');
        await queryInterface.removeColumn('Users', 'document_auth_tag');
        await queryInterface.removeColumn('Users', 'key_version');

        // Add back field-level encryption metadata
        const fields = ['email', 'password', 'firstName', 'lastName'];
        for (const field of fields) {
            await queryInterface.addColumn('Users', `${field}_iv`, {
                type: Sequelize.TEXT,
                allowNull: true
            });
            await queryInterface.addColumn('Users', `${field}_secret_id`, {
                type: Sequelize.TEXT,
                allowNull: true
            });
            await queryInterface.addColumn('Users', `${field}_auth_tag`, {
                type: Sequelize.TEXT,
                allowNull: true
            });
            await queryInterface.addColumn('Users', `${field}_dek`, {
                type: Sequelize.TEXT,
                allowNull: true
            });
        }
    }
}; 