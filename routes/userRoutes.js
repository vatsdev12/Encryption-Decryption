const express = require('express');
const router = express.Router();
const User = require('../models/User');
const sequelize = require('../config/database');
const { Op } = require('sequelize');

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

module.exports = router; 