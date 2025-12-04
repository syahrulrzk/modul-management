const crypto = require('crypto');

// Generate a secure random token
const token = crypto.randomBytes(32).toString('hex');
console.log('Generated Admin Token:', token);

// You can also generate a shorter one if you prefer
const shortToken = crypto.randomBytes(16).toString('hex');
console.log('Short Admin Token:', shortToken);