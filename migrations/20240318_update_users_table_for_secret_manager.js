'use strict';

module.exports = {
    up: async (queryInterface, Sequelize) => {
        // First, drop the old DEK columns
        await queryInterface.removeColumn('Users', 'email_dek');
        await queryInterface.removeColumn('Users', 'password_dek');
        await queryInterface.removeColumn('Users', 'firstName_dek');
        await queryInterface.removeColumn('Users', 'lastName_dek');

        // Add new secret_id columns
        await queryInterface.addColumn('Users', 'email_secret_id', {
            type: Sequelize.TEXT,
            allowNull: true
        });
        await queryInterface.addColumn('Users', 'password_secret_id', {
            type: Sequelize.TEXT,
            allowNull: true
        });
        await queryInterface.addColumn('Users', 'firstName_secret_id', {
            type: Sequelize.TEXT,
            allowNull: true
        });
        await queryInterface.addColumn('Users', 'lastName_secret_id', {
            type: Sequelize.TEXT,
            allowNull: true
        });
    },

    down: async (queryInterface, Sequelize) => {
        // Remove secret_id columns
        await queryInterface.removeColumn('Users', 'email_secret_id');
        await queryInterface.removeColumn('Users', 'password_secret_id');
        await queryInterface.removeColumn('Users', 'firstName_secret_id');
        await queryInterface.removeColumn('Users', 'lastName_secret_id');

        // Add back the old DEK columns
        await queryInterface.addColumn('Users', 'email_dek', {
            type: Sequelize.TEXT,
            allowNull: true
        });
        await queryInterface.addColumn('Users', 'password_dek', {
            type: Sequelize.TEXT,
            allowNull: true
        });
        await queryInterface.addColumn('Users', 'firstName_dek', {
            type: Sequelize.TEXT,
            allowNull: true
        });
        await queryInterface.addColumn('Users', 'lastName_dek', {
            type: Sequelize.TEXT,
            allowNull: true
        });
    }
}; 