import express, { Request, Response, Router } from 'express';
import { Op } from 'sequelize';
import crypto from 'crypto';
import User from '../models/User';
import sequelize from '../config/database';
import encryptionService from '../services/encryptionService';

const router: Router = express.Router();

interface UserSearchFilters {
    email?: string;
    [key: string]: any;
}

interface UserCreateData {
    username: string;
    email: string;
    password: string;
    firstName?: string;
    lastName?: string;
    isActive?: boolean;
}

// Get all users
router.get('/users', async (req: Request, res: Response) => {
    try {
        const users = await User.findAll();
        res.json(users);
    } catch (error) {
        res.status(500).json({
            message: 'Error fetching users',
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
});

// Add a new user
router.post('/users', async (req: Request, res: Response) => {
    try {
        const { username, email, password, firstName, lastName, isActive } = req.body as UserCreateData;

        // Basic validation
        if (!username || !email || !password) {
            res.status(400).json({
                message: 'Username, email and password are required'
            });
            return;
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

        // if (existingUser) {
        //     res.status(400).json({
        //         message: 'Username or email already exists'
        //     });
        //     return;
        // }

        // Create new user - encryption is handled by hooks
        const user = await User.create({
            username,
            email,
            password,
            firstName,
            lastName,
            isActive: isActive ?? true
        });

        res.status(201).json(user);
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({
            message: 'Error creating user',
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
});

// Search users with filters
router.get('/users/search', async (req: Request, res: Response) => {
    try {
        const filters = req.query as UserSearchFilters;
        const whereClause: any = {};

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

        // Find users with filters
        const users = await User.findAll({
            where: whereClause
        });

        if (!users || users.length === 0) {
            res.status(404).json({
                message: 'No users found matching the criteria'
            });
            return;
        }

        res.json({
            count: users.length,
            users: users
        });
    } catch (error) {
        res.status(500).json({
            message: 'Error searching users',
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
});

export default router; 