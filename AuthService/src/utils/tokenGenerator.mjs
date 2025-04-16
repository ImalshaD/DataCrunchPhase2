import jwt from 'jsonwebtoken';
import logger from '@describe/logger';
import convertToSeconds from './reg2seconds.mjs';
import RefreshToken from '../models/RefreshToken.mjs';

const generateToken = (user) =>
  jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  },
  logger.info(`Access token created for user ${user._id}`)
  );
  
const generateRefreshToken = async (user) => {
    
  const token = jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
  });

  const duration = convertToSeconds(process.env.JWT_REFRESH_EXPIRES_IN);
  const expiresAt = new Date(Date.now() + duration * 1000);
  await RefreshToken.create({ token, user: user._id, expiresAt });
  logger.info(`Refresh token created for user ${user._id}`);
  return token;
};
  
export { generateToken, generateRefreshToken };
