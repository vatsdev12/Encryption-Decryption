const express = require('express');
const router = express.Router();
const User = require('../models/User');
const sequelize = require('../config/database');
const { Op } = require('sequelize');
const crypto = require('crypto');

// Helper function to clean user data
const cleanUserData = (user) => {
    if (!user) return null;

    const cleanedData = { ...user.toJSON() };

    // Remove encryption metadata fields
    const fieldsToRemove = [
        'email_iv', 'email_auth_tag',
        'password_iv', 'password_auth_tag',
        'firstName_iv', 'firstName_auth_tag',
        'lastName_iv', 'lastName_auth_tag'
    ];

    fieldsToRemove.forEach(field => {
        delete cleanedData[field];
    });

    return cleanedData;
};

// Get all users
router.get('/', async (req, res) => {
    try {
        const users = await User.findAll();
        const cleanedUsers = users.map(cleanUserData);
        res.json(cleanedUsers);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get user by ID
router.get('/:id', async (req, res) => {
    try {
        const user = await User.findByPk(req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(cleanUserData(user));
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get user by email (using hash)
router.get('/email/:email', async (req, res) => {
    try {
        const emailHash = crypto.createHash('sha256').update(req.params.email.toLowerCase()).digest('hex');
        const user = await User.findOne({ where: { email_hash: emailHash } });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(cleanUserData(user));
    } catch (error) {
        console.error('Error fetching user by email:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Create new user
router.post('/', async (req, res) => {
    try {
        const { username, email, password, firstName, lastName } = req.body;

        // Basic validation
        if (!username || !email || !password) {
            return res.status(400).json({
                error: 'Username, email and password are required'
            });
        }

        // Check if user already exists using email hash
        const emailHash = crypto.createHash('sha256').update(email.toLowerCase()).digest('hex');
        const existingUser = await User.findOne({
            where: {
                [Op.or]: [
                    { username },
                    { email_hash: emailHash }
                ]
            }
        });

        if (existingUser) {
            return res.status(400).json({
                error: 'Username or email already exists'
            });
        }

        const user = await User.create({
            username,
            email,
            password,
            firstName,
            lastName
        });

        res.status(201).json(cleanUserData(user));
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update user
router.put('/:id', async (req, res) => {
    try {
        const user = await User.findByPk(req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // If email is being updated, check for duplicates
        if (req.body.email && req.body.email !== user.email) {
            const emailHash = crypto.createHash('sha256').update(req.body.email.toLowerCase()).digest('hex');
            const existingUser = await User.findOne({
                where: { email_hash: emailHash }
            });

            if (existingUser) {
                return res.status(400).json({
                    error: 'Email already exists'
                });
            }
        }

        await user.update(req.body);
        res.json(cleanUserData(user));
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete user
router.delete('/:id', async (req, res) => {
    try {
        const user = await User.findByPk(req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        await user.destroy();
        res.status(204).send();
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router; 