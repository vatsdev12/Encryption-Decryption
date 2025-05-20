const express = require('express');
const router = express.Router();
const User = require('../models/User');
const sequelize = require('../config/database');
const { Op } = require('sequelize');
const crypto = require('crypto');
const encryptionService = require('../services/encryptionService');

// Get all users
router.get('/users', async (req, res) => {
    try {
        const users = await User.findAll();
        res.json(users);
    } catch (error) {
        res.status(500).json({
            message: 'Error fetching users',
            error: error.message
        });
    }
});

// Add a new user
router.post('/users', async (req, res) => {
    try {
        const { username, email, password, firstName, lastName } = req.body;
        console.log("🚀 ~ router.post ~ req.body:", req.body)

        // Basic validation
        if (!username || !email || !password) {
            return res.status(400).json({
                message: 'Username, email and password are required'
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({
            where: {
                [Op.or]: [
                    { username: username },
                    { email: email }
                ]
            }
        });
        console.log("🚀 ~ router.post ~ existingUser:", existingUser)

        if (existingUser) {
            return res.status(400).json({
                message: 'Username or email already exists'
            });
        }

        // Create new user - encryption is handled by hooks
        const user = await User.create({
            username,
            email,
            password,
            firstName,
            lastName
        });

        res.status(201).json(user);
    } catch (error) {
        res.status(500).json({
            message: 'Error creating user',
            error: error.message
        });
    }
});

// Search users with filters
router.get('/users/search', async (req, res) => {
    try {
        const filters = req.query;
        const whereClause = {};

        // Handle email search with hashing
        if (filters.email) {
            const emailHash = crypto.createHash('sha256')
                .update(filters.email.toLowerCase())
                .digest('hex');
            whereClause.email_hash = emailHash;
            delete filters.email; // Remove email from filters as we've handled it
        }

        // Handle other filters
        Object.keys(filters).forEach(key => {
            if (filters[key]) {
                whereClause[key] = filters[key];
            }
        });

        console.log("Search filters:", whereClause);

        // Find users with filters - remove raw: true to get Sequelize instances
        const users = await User.findAll({
            where: whereClause
        });

        if (!users || users.length === 0) {
            return res.status(404).json({
                message: 'No users found matching the criteria'
            });
        }

        // The decryption is handled by the model's afterFind hook
        res.json({
            count: users.length,
            users: users
        });
    } catch (error) {
        console.error('Error searching users:', error);
        res.status(500).json({
            message: 'Error searching users',
            error: error.message
        });
    }
});

module.exports = router; 