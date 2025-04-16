import fs from 'fs';
import jwt from 'jsonwebtoken';
import User from '../models/User.mjs';
import RefreshToken from '../models/RefreshToken.mjs';
import logger from '@describe/logger';
import convertToSeconds from '../utils/reg2seconds.mjs';
import { StatusCodes } from 'http-status-codes';
import { generateToken, generateRefreshToken } from '../utils/tokenGenerator.mjs';
import { getUserFromToken, invalidateToken, generatePasswordChangeToken} from '../utils/tokenStore.mjs';


const PRIVATE_KEY = fs.readFileSync(path.join(process.cwd(), 'private_auth.key'), 'utf8');

const register = async (req, res, next) => {
  try {
    const { username, password, role } = req.body;

    if (!username || !password) {
      logger.error('Missing registration details');
      return res.status(StatusCodes.BAD_REQUEST).json({ message: 'Incomplete registration details' });
    }
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      logger.error(`User ${username} already exists`);
      return res.status(StatusCodes.CONFLICT).json({ message: 'User already exists' });
    }

    const newUser = new User({ username, password, role });
    await newUser.save();

    res.status(StatusCodes.CREATED).json({ message: 'User registered successfully', user: { id: newUser._id, username: newUser.username, role: newUser.role } });
    logger.info(`User ${username} registered successfully`);
  } catch (err) {
    next(err);
  }
};

const changePasswordInternal = async (req, res) => {
  try {
    console.log('Change password request received:', req.body);
    const { token, newPassword } = req.body;

    const userId = getUserFromToken(token);
    if (!userId) return res.status(StatusCodes.FORBIDDEN).send('Invalid or expired token');

    const user = await User.findById(userId);
    if (!user) return res.status(StatusCodes.NOT_FOUND).send('User not found');

    user.password = newPassword;
    user.loggedIn = true;
    await user.save();
    logger.info(`User ${user.username} changed password successfully`);
    
    invalidateToken(token);
    
    res.redirect('/passwordchanged.html');
    return;
  } catch (err) {
    console.error('Password change error:', err);
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).send('Server error');
  }
};

// Change user password
const changePassword = async (req, res) => {
  try {
    const { username } = req.params;
    const { currentPassword, newPassword } = req.body;
        
    // Verify that users can only update their own password
    if (req.user.username !== username) {
      return res.status(StatusCodes.FORBIDDEN).json({ 
        message: 'You can only change your own password', 
      });
    }

    // Validate request body
    if (!currentPassword || !newPassword) {
      return res.status(StatusCodes.BAD_REQUEST).json({ 
        message: 'Current password and new password are required', 
      });
    }

    const user = await User.findOne({ username });
        
    if (!user) {
      return res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found' });
    }

    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Current password is incorrect' });
    }

    // Check if new password is the same as current password
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(StatusCodes.BAD_REQUEST).json({ 
        message: 'New password must be different from your current password', 
      });
    }
        
    // Update password (will be hashed by pre-save hook)
    user.password = newPassword;
    await user.save();
        
    res.status(StatusCodes.OK).json({ 
      message: 'Password updated successfully',
    });
  } catch (error) {
    console.error('Error in changePassword:', error);
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ 
      message: 'Error updating password', 
      error: error.message, 
    });
  }
};

const login = async (req, res, next) => {
  try{
    const { username, password, returnRefreshTokenInBody } = req.body;

    if (!username || !password) {
      logger.error('Missing Credentials');
      return res.status(StatusCodes.BAD_REQUEST).json({ message: 'Incomplete Request' });
    }
    const user = await User.findOne({ username });    

    if (!user || !(await user.matchPassword(password))) {
      logger.error(`Invalid credentials for user ${username}`);
      return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Invalid credentials' });
    }

    if (!user.loggedIn) {
      logger.info(`User ${username} is logged in for the first time attempting to update password`);
      const changePasswordToken = generatePasswordChangeToken(user._id);
      // res.render('changePassword', { token: changePasswordToken });
      res.json({ redirectUrl: `/ChangePassword.html?token=${changePasswordToken}` });
      // res.redirect(`/ChangePassword.html?token=${changePasswordToken}`);
      return;
    }
    const accessToken = generateToken(user);
    const refreshToken = await generateRefreshToken(user);
    const maxAge = convertToSeconds(process.env.JWT_REFRESH_EXPIRES_IN) * 1000;

    if (returnRefreshTokenInBody) {
      res.json({ 
        token: 'Bearer ' + accessToken, 
        refreshToken: refreshToken,
        user : { id: user._id, username: user.username, role: user.role }
      });
    }
    else{
      res
        .cookie('refreshToken', refreshToken, {
          httpOnly: true,
          secure: false, 
          sameSite: 'Strict',
          maxAge: maxAge,
        })
        .json({
          token: 'Bearer ' + accessToken,
          user: { id: user._id, username: user.username, role: user.role },
        }); 
      }
    logger.info(`User ${username} logged in`);
  } catch (err) {
    next(err);
  }
};

const refreshToken = async (req, res, next) => {
  try{
    // Check if refresh token is in cookies or request body
    // This is to support both cookie-based and body-based refresh token handling
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;

    if (!refreshToken) return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'No refresh token' });

    const stored = await RefreshToken.findOne({ token: refreshToken });
    if (!stored) return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Invalid refresh token' });

    try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      const accessToken = generateToken({ _id: decoded.id });
      res.json({ token: 'Bearer ' + accessToken });
      logger.info(`Refresh token verified for user ${decoded.id}`);
    } catch (err) {
      logger.error(`Error verifying refresh token: ${err.message}`);
      return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Token expired or invalid' });

    }
  }catch (err) {
    next(err);
  }
};

const logout = async (req, res, next) => {
  try {
    const { refreshToken } = req.cookies;
    
    if (refreshToken) {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      await RefreshToken.deleteOne({ token: refreshToken });
      res.clearCookie('refreshToken');
      res.json({ message: 'Logged out successfully' });
      logger.info(`User ${decoded.id} logged out successfully`);
    }else {
      res.json({ message: 'No refresh token' });
      logger.error('No refresh token found');
    } 
  } catch (error) {
    next(error);
  }
};

const getProfile = (req, res, next) => {
  try {
    res.json(req.user);
    logger.info(`Profile retrieved for user ${req.user.username}`);
  } catch (error) {
    next(error);
  }
};


const validate = async (req, res, next) => {
  try {
    // Passport ensures req.user exists
    const user = req.user;
    
    if (!user) {
      logger.error(`Unauthorized, user not found ${user.username}`);
      return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Unauthorized, user not found' });
    }
    
    // Prepare payload for inter-service communication
    const payload = {
      id: user._id,
      username: user.username,
      role: user.role,
      valid: true, // Include validity flag inside the signed response
      iss: 'auth-service',
      iat: Math.floor(Date.now() / 1000),
    };
    
        const signedResponse = jwt.sign(payload, process.env.SIGN_SECRET, {
            algorithm: process.env.SIGN_ALGO || 'HS256',
            expiresIn: process.env.VALIDATE_RESPONSE_EXPIRES_IN || '1m',
        });
        
    res.json({ user: signedResponse });
    logger.info(`User ${user.username} validated`);
  } catch (error) {
    next(error);
  }
};

const validateAssymetric = async (req, res, next) => {
  try {
    const user = req.user;

    if (!user) {
      logger.error(`Unauthorized, user not found`);
      return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Unauthorized, user not found' });
    }

    const payload = {
      id: user._id,
      username: user.username,
      role: user.role,
      valid: true,
      iss: 'auth-service',
      iat: Math.floor(Date.now() / 1000),
    };

    const signedResponse = jwt.sign(payload,PRIVATE_KEY, {
      algorithm: process.env.ASSYMETRIC_SIGN_ALGO || 'RS256',
      expiresIn: process.env.VALIDATE_RESPONSE_EXPIRES_IN || '1m',
    });

    res.json({ user: signedResponse });
    logger.info(`User ${user.username} validated`);
  } catch (error) {
    next(error);
  }
};


export { login, refreshToken, logout, getProfile, validate, 
  register, changePassword, changePasswordInternal, validateAssymetric };
