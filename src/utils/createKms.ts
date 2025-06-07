const createKms = (keyName: string) => {
    const keyRingId = `kr-${keyName}-${Date.now()}`;
    const keyId = `key-${keyName}-${Date.now()}`;
    return { keyRingId, keyId };
}

export default createKms;