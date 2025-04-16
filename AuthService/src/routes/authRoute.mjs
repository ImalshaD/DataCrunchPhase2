import express from 'express';
import passport from 'passport';
import { login, refreshToken, logout, getProfile, validate, validateAssymetric ,changePasswordInternal, register } from '../controllers/authController.mjs';

const router = express.Router();

router.post('/login', login);
router.get('/refresh', refreshToken);
router.post('/logout', logout);
router.get('/validate', passport.authenticate('jwt', { session: false }), validate);
router.get('/validateJWT', passport.authenticate('jwt', { session: false }), validateAssymetric);
router.get('/me', passport.authenticate('jwt', { session: false }), getProfile);
router.post('/change-password', changePasswordInternal);
router.post('/register', register);

export default router;
