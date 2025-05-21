import crypto from 'crypto';

// create hash of the data
const createHash = (data: string): string => {
    return crypto.createHash('sha256').update(data).digest('hex');
};

export default createHash; 