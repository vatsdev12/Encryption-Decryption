const { sequelize } = require('../config/database');
const User = require('./User');
const ClientKey = require('./ClientKey');

// Export models
module.exports = {
    sequelize,
    User,
    ClientKey
}; 