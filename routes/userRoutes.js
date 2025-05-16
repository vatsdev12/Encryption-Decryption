const express = require('express');
const router = express.Router();
const User = require('../models/User');
const sequelize = require('../config/database');
const { Op } = require('sequelize');
const encryptionService = require('../services/encryptionService');

// Get all users
router.get('/users', async (req, res) => {
    try {
        const users = await User.findAll();
        // Decrypt user data
        const decryptedUsers = await Promise.all(
            users.map(user => encryptionService.decryptObject('User', user.toJSON()))
        );
        res.json(decryptedUsers);
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

        // Encrypt sensitive data
        const encryptedData = await encryptionService.encryptObject('User', {
            username,
            email,
            password,
            firstName,
            lastName
        });
        // Create new user with encrypted data
        const user = await User.create(encryptedData);

        // Return decrypted user data (excluding password)
        // const decryptedUser = await encryptionService.decryptObject('User', user.toJSON());
        // const { password: _, ...userWithoutPassword } = decryptedUser;
        res.status(201).json(user);
    } catch (error) {
        res.status(500).json({
            message: 'Error creating user',
            error: error.message
        });
    }
});

module.exports = router; 