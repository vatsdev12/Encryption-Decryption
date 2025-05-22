// check in cache if at any userid the dek is cached or not
import cacheService from '../services/cacheService';
import UserKeyDetails from '../models/UserKeyDetails';

export const checkKMS = async (kmsKeyName: string, userId: number) => {
    const secretId = `secret-${kmsKeyName}`;
    const cachedData = cacheService.get(secretId);
    console.log("🚀 ~ checkKMS ~ cachedData:", cachedData)
    if (cachedData) {
        return {
            userKeyDetails: {
                locationId: cachedData.locationId,
                keyRingId: cachedData.keyRingId,
                keyId: cachedData.keyId,
                secretId: cachedData.secretId,
                encryptedDEK: cachedData.encryptedDEK
            },
            isCached: true,
            isUserKeyDetails: false
        };
    }
    const userKeyDetails = await UserKeyDetails.findOne({
        where: {
            userId: userId
        }
    });
    if (userKeyDetails) {
        return {
            userKeyDetails: {
                locationId: userKeyDetails.locationId,
                keyRingId: userKeyDetails.keyRingId,
                keyId: userKeyDetails.keyId,
                secretId: userKeyDetails.secretId
            },
            isCached: false,
            isUserKeyDetails: true
        };
    }
    return {
        userKeyDetails: {
            locationId: null,
            keyRingId: null,
            keyId: null,
            secretId: null
        },
        isCached: false,
        isUserKeyDetails: false
    };
}