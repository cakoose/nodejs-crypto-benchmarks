import assert from 'assert';
import * as crypto from 'crypto';

import {Registry} from "../impl";

const AEAD_AUTH_FAILED_EXCEPTION_MESSAGE = 'Unsupported state or unable to authenticate data';

export const register = async (r: Registry): Promise<void> => {
    const source = 'Node crypto';
    const macKey = r.macKey;

    // createHash, createHmac
    for (const [name, ident] of [
        ["MD5 (insecure)", 'md5'],
        ["SHA-1 (insecure)", 'sha1'],
        ["SHA-2-256", 'sha256'],
        ["SHA-2-512", 'sha512'],
        ['SHA-3-256', 'sha3-256'],
        ['SHA-3-512', 'sha3-512'],
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
    for (const numBits of [128, 256]) {
        const outputNumBits = numBits * 2;
        const name = `SHAKE-${numBits}`;
        const ident = `shake${numBits}`;
        r.hashAlgos.push({name, source, impl: {streaming: handler => handler({
            construct: () => crypto.createHash(ident, {outputLength: outputNumBits}),
            update: (state, data) => { state.update(data); },
            final: state => state.digest(),
        })}});
    }

    r.macAlgos.push({name: "SHA-2-512 prefix-MAC trunc 256", source, impl: {streaming: handler => handler({
        construct: () => crypto.createHash('sha512').update(macKey),
        update: (state, data) => { state.update(data); },
        final: state => state.digest(),
    })}});

    // AEADs
    for (const [ident, name, keyNumBits, ivNumBits] of [
        ['aes-128-gcm', 'AES-128-GCM', 128, 96],
        ['aes-256-gcm', 'AES-256-GCM', 256, 96],
        ['aes-128-ccm', 'AES-128-CCM', 128, 96],
        ['aes-256-ccm', 'AES-256-CCM', 256, 96],
        ['aes-128-ocb', 'AES-128-OCB', 128, 96],
        ['aes-256-ocb', 'AES-256-OCB', 256, 96],
        ['chacha20-poly1305', 'ChaCha20-Poly1305', 256, 96],
    ] as Array<[crypto.CipherCCMTypes, string, number, number]>) {
        assert(keyNumBits % 8 === 0);
        const keyNumBytes = keyNumBits / 8;
        const key = Buffer.alloc(keyNumBytes);
        assert(ivNumBits % 8 === 0);
        const ivNumBytes = ivNumBits / 8;
        r.symmetricEncryptAndAuthAlgos.push({name, source, impl: {
            ivNumBytes,
            encryptAndAuth: (iv, input) => {
                const cipher = crypto.createCipheriv(ident, key, iv, {authTagLength: 16});
                const cipherText = cipher.update(input);
                const cipherTextFinal = cipher.final();
                assert(cipherTextFinal.length === 0); // If not empty, we would have to append to 'cipherText'.
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
                    if ((err as any).message === AEAD_AUTH_FAILED_EXCEPTION_MESSAGE) return null;
                    throw err;
                }
                assert(plainTextFinal.length === 0);
                return [plainText];
            },
        }});
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

    // randomBytes
    r.randomAlgos.push({name: 'randomFillSync', source, impl: crypto.randomFillSync});
};
