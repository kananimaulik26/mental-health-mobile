const crypto = require('crypto');

const generateSecretHash = (email, clientId, clientSecret) => {
  return crypto
    .createHmac('sha256', clientSecret)
    .update(email + clientId)
    .digest('base64');
};

module.exports = { generateSecretHash };
