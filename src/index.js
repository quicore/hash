import crypto from 'crypto';

/**
 * Provides a faster and unified interface to commonly used cryptographic hash functions.
 * Includes support for SHA families, BLAKE2, PBKDF2, RIPEMD, and more.
 * Ideal for generating IDs, digital fingerprints, and secure hashes in Node.js applications.
 */
export class GenerateHash {
    /** Base62 character set used for compact encoding */
    static BASE62_CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    /** Default length for generated Base62-encoded IDs */
    static DEFAULT_ID_LENGTH = 22;

    /** Minimum allowed length for Base62-encoded IDs */
    static MIN_ID_LENGTH = 10;

    /** Digest size (in bytes) for BLAKE2b hashes used in compact ID generation */
    static BLAKE2B_DIGEST_SIZE = 20;

    /**
     * Converts a binary buffer to a Base62-encoded string.
     *
     * @param {Buffer} buffer - The binary data to encode.
     * @param {number} [length=GenerateHash.DEFAULT_ID_LENGTH] - Desired output length. Must be ≥ MIN_ID_LENGTH.
     * @returns {string} Base62-encoded string.
     * @throws {Error} If the requested length is below the minimum threshold.
     */
    static toBase62(buffer, length = this.DEFAULT_ID_LENGTH) {
        if (length < this.MIN_ID_LENGTH) {
            throw new Error(`ID length must be at least ${this.MIN_ID_LENGTH} characters`);
        }

        let num = BigInt('0x' + buffer.toString('hex'));
        let result = '';
        const base = BigInt(this.BASE62_CHARS.length);

        do {
            const remainder = Number(num % base);
            result = this.BASE62_CHARS[remainder] + result;
            num = num / base;
        } while (num > 0n);

        return result.length > length
            ? result.substring(0, length)
            : result.padStart(length, '0');
    }

    /**
     * Generates a BLAKE2b hash from the input string.
     *
     * @param {string | Buffer} input - The input data to hash.
     * @param {number} [digestSize=GenerateHash.BLAKE2B_DIGEST_SIZE] - Length of the digest in bytes.
     * @returns {Buffer} Hash output as a buffer.
     */
    static blake2b(input, digestSize = this.BLAKE2B_DIGEST_SIZE) {
        return crypto.createHash('blake2b', { digestLength: digestSize })
            .update(input)
            .digest();
    }

    /**
     * Generates a compact, MongoDB-friendly hash string using BLAKE2b and Base62 encoding.
     *
     * @param {string} input - Input string to hash.
     * @param {number} [length=GenerateHash.DEFAULT_ID_LENGTH] - Desired output length of the encoded hash.
     * @returns {string} Base62-encoded BLAKE2b hash string.
     */
    static compactHash(input, length = this.DEFAULT_ID_LENGTH) {
        const hash = this.blake2b(input);
        return this.toBase62(hash, length);
    }

    /**
     * Generates a SHA-256 hash of the input.
     *
     * @param {string} input - The input string to hash.
     * @returns {string} Hexadecimal representation of the SHA-256 hash.
     */
    static SHA256(input) {
        return crypto.createHash('sha256').update(input).digest('hex');
    }

    /**
     * Generates an MD5 hash of the input.
     *
     * @deprecated MD5 is not secure for cryptographic or security-sensitive operations.
     * @param {string} input - The input string to hash.
     * @returns {string} Hexadecimal representation of the MD5 hash.
     */
    static MD5(input) {
        return crypto.createHash('md5').update(input).digest('hex');
    }

    /**
     * Generates a SHA-1 hash of the input.
     *
     * @deprecated SHA-1 is not secure for cryptographic or security-sensitive operations.
     * @param {string} input - The input string to hash.
     * @returns {string} Hexadecimal representation of the SHA-1 hash.
     */
    static SHA1(input) {
        return crypto.createHash('sha1').update(input).digest('hex');
    }

    /**
     * Generates a SHA3-256 hash of the input.
     *
     * @param {string} input - The input string to hash.
     * @returns {string} Hexadecimal representation of the SHA3-256 hash.
     */
    static SHA3_256(input) {
        return crypto.createHash('sha3-256').update(input).digest('hex');
    }

    /**
     * Generates a PBKDF2 hash using SHA-512.
     *
     * @param {string} password - The password to hash.
     * @param {string} salt - The salt to use in the hashing process.
     * @returns {string} Hexadecimal representation of the derived key.
     */
    static PBKDF2(password, salt) {
        const iterations = 100000;
        const keyLength = 64;
        return crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha512').toString('hex');
    }

    /**
     * Generates a SHA-512 hash.
     * @param {string} input - Input string to hash.
     * @returns {string} Hexadecimal SHA-512 hash.
     */
    static SHA512(input) {
        return crypto.createHash('sha512').update(input).digest('hex');
    }

    /**
     * Generates a SHA3-512 hash.
     * @param {string} input - Input string to hash.
     * @returns {string} Hexadecimal SHA3-512 hash.
     */
    static SHA3_512(input) {
        return crypto.createHash('sha3-512').update(input).digest('hex');
    }

    /**
     * Generates a RIPEMD-160 hash.
     * @param {string} input - Input string to hash.
     * @returns {string} Hexadecimal RIPEMD-160 hash.
     */
    static RIPEMD160(input) {
        return crypto.createHash('ripemd160').update(input).digest('hex');
    }

    /**
     * Generates a BLAKE2s256 hash.
     * @param {string} input - Input string to hash.
     * @returns {string} Hexadecimal BLAKE2s256 hash.
     */
    static BLAKE2s256(input) {
        return crypto.createHash('blake2s256').update(input).digest('hex');
    }
}
