// FILE: auth.js
// ROLE: Secure verification middleware using JWT signatures
// INSPIRED BY: Production-grade fraud-ops API gateways
// PERFORMANCE TARGET: Cryptographic verification check under 1ms
const jwt = require('jsonwebtoken');

module.exports = function auth(req, res, next) {
  // 1. Grab the authorization header
  const authHeader = req.headers['authorization'];
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ 
      error: 'Access Denied: No authentication token provided.' 
    });
  }

  // 2. Extract the token from the "Bearer <token>" format
  const token = authHeader.split(' ')[1];

  try {
    // 3. Make sure our secure server-side JWT_SECRET is configured
    if (!process.env.JWT_SECRET) {
      console.error("SECURITY CRITICAL CONFIG ERROR: JWT_SECRET environment variable is missing.");
      return res.status(500).json({ error: 'Internal server configuration error.' });
    }

    // 4. Cryptographically verify the token signature and expiration
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    
    // 5. Securely populate req.user from trusted token payload data
    req.user = {
      id: verified.id || verified.userId,
      role: verified.role || 'analyst'
    };

    next();
  } catch (error) {
    // 6. Handle bad, expired, or forged tokens
    return res.status(403).json({ 
      error: 'Access Denied: Invalid or expired authentication token.' 
    });
  }
};