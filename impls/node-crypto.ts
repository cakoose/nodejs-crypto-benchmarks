import * as assert from 'assert';
import * as crypto from 'crypto';
import * as process from 'process';
import * as semver from 'semver';

import {Registry} from "../impl";

const EMPTY_BUFFER = Buffer.alloc(0);
const AEAD_AUTH_FAILED_EXCEPTION_MESSAGE = 'Unsupported state or unable to authenticate data';

export const register = async (r: Registry) => {
    const source = 'Node crypto';
    const macKey = r.macKey;
    const nodeVersion = process.version;

    // createHash, createHmac
    for (const [name, ident] of [
        ["MD5 (insecure)", 'md5'],
        ["SHA-1 (insecure)", 'sha1'],
        ["SHA-2-256", 'sha256'],
        ["SHA-2-512", 'sha512'],
    ]) {
        r.hashAlgos.push({name, source, impl: {streaming: handler => handler({
            construct: () => crypto.createHash(ident),
            update: (state, data) => { state.update(data); },
            final: state => state.digest(),
        })}});
        r.macAlgos.push({name: `HMAC-${name}`, source, impl: {streaming: handler => handler({
            construct: () => crypto.createHmac(ident, macKey),
            update: (state, data) => { state.update(data); },
            final: state => state.digest(),
        })}});
    }

    r.macAlgos.push({name: "SHA-2-512 prefix-MAC trunc 256", source, impl: {streaming: handler => handler({
        construct: () => crypto.createHash('sha512').update(macKey),
        update: (state, data) => { state.update(data); },
        final: state => state.digest(),
    })}});

    // AES-GCM
    for (const [ident, keyNumBits] of [
        ['aes-128-gcm', 128],
        ['aes-256-gcm', 256],
    ] as Array<[crypto.CipherGCMTypes, number]>) {
        assert(keyNumBits % 8 === 0);
        const keyNumBytes = keyNumBits / 8;
        const key = Buffer.alloc(keyNumBytes);
        r.symmetricEncryptAndAuthAlgos.push({name: `AES-${keyNumBits}-GCM`, source, impl: {
            ivNumBytes: 12,
            encryptAndAuth: (iv, input) => {
                const cipher = crypto.createCipheriv(ident, key, iv);
                cipher.setAAD(EMPTY_BUFFER);
                const cipherText = cipher.update(input);
                const cipherTextFinal = cipher.final();
                assert(cipherTextFinal.length === 0);  // If not empty, we would have to append to 'cipherText'.
                const authTag = cipher.getAuthTag();
                return [cipherText, authTag];
            },
            verifyDecrypt: (iv, [cipherText, authTag]) => {
                const decipher = crypto.createDecipheriv(ident, key, iv);
                decipher.setAAD(EMPTY_BUFFER);
                decipher.setAuthTag(authTag);
                const plainText = decipher.update(cipherText);
                let plainTextFinal;
                try {
                    plainTextFinal = decipher.final();
                } catch (err) {
                    if (err.message === AEAD_AUTH_FAILED_EXCEPTION_MESSAGE) return null;
                    throw err;
                }
                assert(plainTextFinal.length === 0);
                return [plainText];
            },
        }});
    }

    // AES-CCM
    if (semver.satisfies(nodeVersion, '9.x')) {
        for (const [ident, keyNumBits] of [
            ['aes-128-ccm', 128],
            ['aes-256-ccm', 256],
        ] as Array<[crypto.CipherCCMTypes, number]>) {
            assert(keyNumBits % 8 === 0);
            const keyNumBytes = keyNumBits / 8;
            const key = Buffer.alloc(keyNumBytes);
            r.symmetricEncryptAndAuthAlgos.push({name: `AES-${keyNumBits}-CCM`, source, impl: {
                ivNumBytes: 12,  // Can use different values; a 12-byte IV means the plaintext can be at most 16MB.
                encryptAndAuth: (iv, input) => {
                    const cipher = crypto.createCipheriv(ident, key, iv, {authTagLength: 16});
                    const cipherText = cipher.update(input);
                    const cipherTextFinal = cipher.final();
                    assert(cipherTextFinal.length === 0);  // If not empty, we would have to append to 'cipherText'.
                    const authTag = cipher.getAuthTag();
                    return [cipherText, authTag];
                },
                verifyDecrypt: (iv, [cipherText, authTag]) => {
                    const decipher = crypto.createDecipheriv(ident, key, iv, {authTagLength: 16});
                    decipher.setAuthTag(authTag);
                    const plainText = decipher.update(cipherText);
                    let plainTextFinal;
                    try {
                        plainTextFinal = decipher.final();
                    } catch (err) {
                        if (err.message === AEAD_AUTH_FAILED_EXCEPTION_MESSAGE) return null;
                        throw err;
                    }
                    assert(plainTextFinal.length === 0);
                    return [plainText];
                },
            }});
        }
    }

    // AES-OCB
    if (semver.satisfies(nodeVersion, '9.x')) {
        for (const [ident, keyNumBits] of [
            ['aes-128-ocb', 128],
            ['aes-256-ocb', 256],
        ] as Array<[string, number]>) {
            assert(keyNumBits % 8 === 0);
            const keyNumBytes = keyNumBits / 8;
            const key = Buffer.alloc(keyNumBytes);
            r.symmetricEncryptAndAuthAlgos.push({name: `AES-${keyNumBits}-OCB`, source, impl: {
                ivNumBytes: 12,  // Can use different values; a 12-byte IV means the plaintext can be at most 16MB.
                encryptAndAuth: (iv, input) => {
                    // NOTE: We're casting to crypto.CipherGCMTypes because the Node type defintions
                    // we're using doesn't have good types for OFB mode.
                    const cipher = crypto.createCipheriv(ident as crypto.CipherGCMTypes, key, iv, {authTagLength: 16});
                    cipher.setAAD(EMPTY_BUFFER);
                    const cipherText = cipher.update(input);
                    const cipherTextFinal = cipher.final();
                    assert(cipherTextFinal.length === 0);  // If not empty, we would have to append to 'cipherText'.
                    const authTag = cipher.getAuthTag();
                    return [cipherText, authTag];
                },
                verifyDecrypt: (iv, [cipherText, authTag]) => {
                    const decipher = crypto.createDecipheriv(ident as crypto.CipherGCMTypes, key, iv, {authTagLength: 16});
                    decipher.setAAD(EMPTY_BUFFER);
                    decipher.setAuthTag(authTag);
                    const plainText = decipher.update(cipherText);
                    let plainTextFinal;
                    try {
                        plainTextFinal = decipher.final();
                    } catch (err) {
                        if (err.message === AEAD_AUTH_FAILED_EXCEPTION_MESSAGE) return null;
                        throw err;
                    }
                    assert(plainTextFinal.length === 0);
                    return [plainText];
                },
            }});
        }
    }

    // AES-CTR/CBC + HMAC-SHA-2
    for (const [ident, aesKeyNumBits, aesMode, sha2Bits] of [
        ['aes-128-cbc', 128, 'CBC', 256],
        ['aes-256-cbc', 256, 'CBC', 512],
        ['aes-128-ctr', 128, 'CTR', 256],
        ['aes-256-ctr', 256, 'CTR', 512],
    ] as Array<[string, number, string, number]>) {
        assert(aesKeyNumBits % 8 === 0);
        const aesKeyNumBytes = aesKeyNumBits / 8;
        const aesKey = Buffer.alloc(aesKeyNumBytes);
        assert(sha2Bits % 8 === 0);
        const sha2Bytes = sha2Bits / 8;
        const hashAlgo = `sha${sha2Bits}`;
        assert(sha2Bytes % 2 === 0);
        const authTagNumBytes = sha2Bytes / 2;
        r.symmetricEncryptAndAuthAlgos.push({name: `AES-${aesKeyNumBits}-${aesMode} + HMAC-SHA-2-${sha2Bits} trunc ${sha2Bits/2}`, source, impl: {
            ivNumBytes: 16,
            encryptAndAuth: (iv, input) => {
                const cipher = crypto.createCipheriv(ident, aesKey, iv);
                const cipherText1 = cipher.update(input);
                const cipherText2 = cipher.final();
                const hasher = crypto.createHash(hashAlgo);
                hasher.update(macKey);
                hasher.update(iv);
                hasher.update(cipherText1);
                hasher.update(cipherText2);
                const authTag = hasher.digest().slice(0, authTagNumBytes);
                return [cipherText1, cipherText2, authTag];
            },
            verifyDecrypt: (iv, [cipherText, cipherTextFinal, authTag]) => {
                if (authTag.length !== authTagNumBytes) return null;
                const decipher = crypto.createDecipheriv(ident, aesKey, iv);
                const hasher = crypto.createHash(hashAlgo);
                hasher.update(macKey);
                hasher.update(iv);
                hasher.update(cipherText);
                hasher.update(cipherTextFinal);
                const expectedAuthTag = hasher.digest().slice(0, authTagNumBytes);
                if (!crypto.timingSafeEqual(expectedAuthTag, authTag)) return null;
                const plainText1 = decipher.update(cipherText);
                const plainText2 = decipher.update(cipherTextFinal);
                const plainTextFinal = decipher.final();
                assert(plainTextFinal.length === 0);
                return [plainText1, plainText2];
            },
        }});
    }

    // ChaCha20-Poly1305
    {
        // TODO: Not working right now (Error: Invalid state for operation getAuthTag)
        // TODO: Need to update NPM package "@types/node" to recognize 'chacha20-poly1305' as an AEAD Cipher
        // const ident = ('chacha20-poly1305' as crypto.CipherGCMTypes);
        // addAead(`ChaCha20-Poly1305`, ident, {keyNumBytes: 32, ivNumBytes: 12});
    }

    // randomBytes
    r.randomAlgos.push({name: 'randomFillSync', source, impl: crypto.randomFillSync});
};
