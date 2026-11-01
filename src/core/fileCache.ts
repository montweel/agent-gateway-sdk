import fs from "fs";

export interface FileCache<T> {
  /** Parsed contents. Re-reads only when the file's mtime or size changed. */
  get(): T;
  /** Forget the cached value (call right after writing the file yourself). */
  invalidate(): void;
}

/**
 * In-memory cache for a small JSON file. A stat() per call is far cheaper than
 * reading and parsing on every request, and edits made by hand still apply live.
 * `parse` receives the file text, or null when the file does not exist.
 */
export function createFileCache<T>(filePath: string, parse: (text: string | null) => T): FileCache<T> {
  let cached: { mtimeMs: number; size: number; value: T } | undefined;

  return {
    get() {
      let mtimeMs = -1;
      let size = -1;
      try {
        const st = fs.statSync(filePath);
        mtimeMs = st.mtimeMs;
        size = st.size;
      } catch {
        // missing file: cached below as "does not exist"
      }
      if (cached && cached.mtimeMs === mtimeMs && cached.size === size) return cached.value;

      let text: string | null = null;
      if (mtimeMs !== -1) {
        try {
          text = fs.readFileSync(filePath, "utf-8");
        } catch {
          text = null;
        }
      }
      const value = parse(text);
      cached = { mtimeMs, size, value };
      return value;
    },
    invalidate() {
      cached = undefined;
    },
  };
}
