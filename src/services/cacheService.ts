// Cache service to cache the data in memory

class CacheService {
    private cache: Map<string, Buffer>;

    constructor() {
        this.cache = new Map();
    }

    get(key: string): any {
        return this.cache.get(key);
    }

    set(key: string, value: any): void {
        this.cache.set(key, value);
    }

    delete(key: string): void {
        this.cache.delete(key);
    }

    clear(): void {
        this.cache.clear();
    }
}

export default new CacheService();
