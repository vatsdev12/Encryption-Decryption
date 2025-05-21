const createKms = (keyName: string) => {
    const keyRingId = `kr-${keyName}`;
    const keyId = `key-${keyName}`;
    return { keyRingId, keyId };
}

export default createKms;