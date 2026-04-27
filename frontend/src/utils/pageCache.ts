const pageCache = new Map<string, unknown>();

export function getPageCache<T>(key: string): T | undefined {
  return pageCache.get(key) as T | undefined;
}

export function setPageCache<T>(key: string, value: T) {
  pageCache.set(key, value);
}

export function clearPageCache(key: string) {
  pageCache.delete(key);
}
