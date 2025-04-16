// utils/tokenStore.js
import logger from "@describe/logger";

const tokenMap = new Map(); // token => { userId, expiresAt }

function generatePasswordChangeToken(userId) {
  const token = crypto.randomUUID(); // Or use uuid module
  const expiresAt = Date.now() + 1000 * 60 * 5; // 1 minute
  tokenMap.set(token, { userId, expiresAt });
  return token;
}

function getUserFromToken(token) {
  console.log('Token:', token);
  const entry = tokenMap.get(token);
  if (!entry || Date.now() > entry.expiresAt) {
    tokenMap.delete(token); // auto-clean expired token
    return null;
  }
  return entry.userId;
}

function invalidateToken(token) {
  tokenMap.delete(token);
}

function cleanupExpiredTokens() {
    logger.info('Cleaning up expired tokens...');
    const now = Date.now();
    for (const [token, { expiresAt }] of tokenMap.entries()) {
        if (expiresAt < now) {
        tokenMap.delete(token);
        }
    }
}

setInterval(cleanupExpiredTokens, 1000 * 60 * 10);

export { generatePasswordChangeToken, getUserFromToken, invalidateToken };
