import './config/env.mjs';
import express from 'express';
import logger from '@describe/logger';
import connectDB from './config/database.mjs';
import passport from 'passport';
import initPassport from './config/passport.mjs';
import authRoutes from './routes/authRoute.mjs';
import cookieParser from 'cookie-parser';
import {StatusCodes} from 'http-status-codes';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const VERSION = 5.2;
const PORT = process.env.PORT || 3001;

const app = express();
app.use(cors({
  origin: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'UPDATE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true, // Disable credentials for all origins
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Connect DB
connectDB();

// Passport config
initPassport(passport);
app.use(passport.initialize());

app.use(express.static(path.join(__dirname, 'views')));
app.use('/static', express.static(path.join(__dirname, 'public')));

// Set the views directory
app.set('views', path.join(__dirname, 'views'));


app.set('view engine', 'ejs');
app.use('/api/auth', authRoutes);


// Basic health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'Auth Service is running' });
  logger.info('Health check endpoint was called');
});


app.use((err, req, res, next) => {
  logger.info(err.message); // Log the error
  res.status(err.status || StatusCodes.INTERNAL_SERVER_ERROR).json({
    message: 'Internal Server Error',
  });
});

app.listen(PORT, () => {
  console.log(`Auth service listening on port ${PORT}, version: ${VERSION}`);
});
