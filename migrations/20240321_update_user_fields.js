'use strict';

module.exports = {
    up: async (queryInterface, Sequelize) => {
        // Change id column to UUID
        await queryInterface.changeColumn('Users', 'id', {
            type: Sequelize.UUID,
            defaultValue: Sequelize.UUIDV4,
            primaryKey: true
        });

        // Add field-level encryption metadata
        await queryInterface.addColumn('Users', 'email_iv', {
            type: Sequelize.TEXT,
            allowNull: true
        });
        await queryInterface.addColumn('Users', 'email_auth_tag', {
            type: Sequelize.TEXT,
            allowNull: true
        });
        await queryInterface.addColumn('Users', 'password_iv', {
            type: Sequelize.TEXT,
            allowNull: true
        });
        await queryInterface.addColumn('Users', 'password_auth_tag', {
            type: Sequelize.TEXT,
            allowNull: true
        });
        await queryInterface.addColumn('Users', 'firstName_iv', {
            type: Sequelize.TEXT,
            allowNull: true
        });
        await queryInterface.addColumn('Users', 'firstName_auth_tag', {
            type: Sequelize.TEXT,
            allowNull: true
        });
        await queryInterface.addColumn('Users', 'lastName_iv', {
            type: Sequelize.TEXT,
            allowNull: true
        });
        await queryInterface.addColumn('Users', 'lastName_auth_tag', {
            type: Sequelize.TEXT,
            allowNull: true
        });

        // Remove document-level encryption metadata
        await queryInterface.removeColumn('Users', 'document_iv');
        await queryInterface.removeColumn('Users', 'document_secret_id');
        await queryInterface.removeColumn('Users', 'document_auth_tag');
    },

    down: async (queryInterface, Sequelize) => {
        // Change id column back to INTEGER
        await queryInterface.changeColumn('Users', 'id', {
            type: Sequelize.INTEGER,
            primaryKey: true,
            autoIncrement: true
        });

        // Remove field-level encryption metadata
        await queryInterface.removeColumn('Users', 'email_iv');
        await queryInterface.removeColumn('Users', 'email_auth_tag');
        await queryInterface.removeColumn('Users', 'password_iv');
        await queryInterface.removeColumn('Users', 'password_auth_tag');
        await queryInterface.removeColumn('Users', 'firstName_iv');
        await queryInterface.removeColumn('Users', 'firstName_auth_tag');
        await queryInterface.removeColumn('Users', 'lastName_iv');
        await queryInterface.removeColumn('Users', 'lastName_auth_tag');

        // Add back document-level encryption metadata
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
    }
}; 