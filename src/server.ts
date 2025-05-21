import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import sequelize from './config/database';
import User from './models/User';
import userRoutes from './routes/userRoutes';

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api', userRoutes);

// Basic route
app.get('/', (req: Request, res: Response) => {
    res.json({ message: 'Welcome to the server!' });
});

// Database connection and server start
const startServer = async (): Promise<void> => {
    try {
        // Test database connection
        await sequelize.authenticate();

        // Sync database (creates tables if they don't exist)
        await sequelize.sync();

        // Start server
        app.listen(port, () => {
            console.log(`Server is running on port ${port}`);
        });
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
};

startServer(); 