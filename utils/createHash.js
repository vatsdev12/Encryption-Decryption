const crypto = require('crypto');

// create hash of the data
const createHash = (data) => {
    return crypto.createHash('sha256').update(data).digest('hex');
}

module.exports = createHash;