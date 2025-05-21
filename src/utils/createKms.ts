const createKms = (username: string) => {
    const keyRingId = `kr-${username}`;
    const keyId = `key-${username}`;
    return { keyRingId, keyId };
}

export default createKms;