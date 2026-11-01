"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createFileCache = createFileCache;
const fs_1 = __importDefault(require("fs"));
/**
 * In-memory cache for a small JSON file. A stat() per call is far cheaper than
 * reading and parsing on every request, and edits made by hand still apply live.
 * `parse` receives the file text, or null when the file does not exist.
 */
function createFileCache(filePath, parse) {
    let cached;
    return {
        get() {
            let mtimeMs = -1;
            let size = -1;
            try {
                const st = fs_1.default.statSync(filePath);
                mtimeMs = st.mtimeMs;
                size = st.size;
            }
            catch {
                // missing file: cached below as "does not exist"
            }
            if (cached && cached.mtimeMs === mtimeMs && cached.size === size)
                return cached.value;
            let text = null;
            if (mtimeMs !== -1) {
                try {
                    text = fs_1.default.readFileSync(filePath, "utf-8");
                }
                catch {
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
