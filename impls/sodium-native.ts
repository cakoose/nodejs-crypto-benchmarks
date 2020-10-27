const sodiumNative = require('sodium-native');

import {Registry} from "../impl";

// TODO: sodium-native's API lets us reuse state buffers and output buffers.  Maybe include
// a variant where we test that use case?
export const register = async (r: Registry) => {
    const source = "NPM sodium-native";
    r.packages.add('sodium-native');

    const macKey = r.macKey;

    // crypto_hash
    for (const [name, ident] of [
        ["SHA-2-256", 'sha256'],
        ["SHA-2-512", 'sha512'],
    ]) {
        const oneShot = sodiumNative[`crypto_hash_${ident}`];
        const outputNumBytes = sodiumNative[`crypto_hash_${ident}_BYTES`];
        const stateNumBytes = sodiumNative[`crypto_hash_${ident}_STATEBYTES`];
        const initFn = sodiumNative[`crypto_hash_${ident}_init`];
        const updateFn = sodiumNative[`crypto_hash_${ident}_update`];
        const finalFn = sodiumNative[`crypto_hash_${ident}_final`];
        r.hashAlgos.push({name, source, impl: {
            oneShot: input => {
                const outputBuffer = Buffer.allocUnsafe(outputNumBytes);
                oneShot(outputBuffer, input);
                return outputBuffer;
            },
            streaming: handler => handler({
                construct: () => {
                    const state = Buffer.allocUnsafe(stateNumBytes);
                    initFn(state);
                    return state;
                },
                update: (state, data) => { updateFn(state, data); },
                final: state => {
                    const outputBuffer = Buffer.allocUnsafe(outputNumBytes);
                    finalFn(state, outputBuffer);
                    return outputBuffer;
                },
            }),
        }});
    }

    // crypto_generichash (not part of the function name, but it's 'blake2b')
    {
        const outputNumBytes = 64;
        const oneShot: (output: Buffer, input: Buffer, key?: Buffer) => void = sodiumNative.crypto_generichash;
        const construct = (key: Buffer | null, outputNumBytes: number): Buffer => {
            const state = Buffer.allocUnsafe(sodiumNative.crypto_generichash_STATEBYTES);
            sodiumNative.crypto_generichash_init(state, key, outputNumBytes);
            return state;
        };
        r.hashAlgos.push({name: 'BLAKE2b', source, impl: {
            oneShot: input => {
                const outputBuffer = Buffer.allocUnsafe(outputNumBytes);
                oneShot(outputBuffer, input);
                return outputBuffer;
            },
            streaming: handler => handler({
                construct: () => construct(null, outputNumBytes),
                update: (state, data) => { sodiumNative.crypto_generichash_update(state, data); },
                final: state => {
                    const outputBuffer = Buffer.allocUnsafe(outputNumBytes);
                    sodiumNative.crypto_generichash_final(state, outputBuffer);
                    return outputBuffer;
                },
            }),
        }});
        r.macAlgos.push({name: `BLAKE2b with key`, source, impl: {
            oneShot: input => {
                const outputBuffer = Buffer.allocUnsafe(outputNumBytes);
                oneShot(outputBuffer, input, macKey);
                return outputBuffer;
            },
            streaming: handler => handler({
                construct: () => construct(macKey, outputNumBytes),
                update: (state, data) => { sodiumNative.crypto_generichash_update(state, data); },
                final: state => {
                    const outputBuffer = Buffer.allocUnsafe(outputNumBytes);
                    sodiumNative.crypto_generichash_final(state, outputBuffer);
                    return outputBuffer;
                },
            }),
        }});
    }

    // crypto_sign (not part of the function name, but it's 'ed25519')
    {
        const seedBuffer = Buffer.alloc(sodiumNative.crypto_sign_SEEDBYTES);
        const secretKey = Buffer.alloc(sodiumNative.crypto_sign_SECRETKEYBYTES);
        const publicKey = Buffer.alloc(sodiumNative.crypto_sign_PUBLICKEYBYTES);
        sodiumNative.crypto_sign_seed_keypair(publicKey, secretKey, seedBuffer);
        const sign = sodiumNative.crypto_sign_detached;
        const verify = sodiumNative.crypto_sign_verify_detached;
        r.asymmetricSignAlgos.push({name: 'Ed25519 SHA-512', source, impl: {
            sign: message => {
                const signature = Buffer.allocUnsafe(sodiumNative.crypto_sign_BYTES);
                sign(signature, message, secretKey);
                return signature;
            },
            verify: (signature, message) => verify(signature, message, publicKey),
        }});
    }

    // crypto_secretbox (not part of the function name, but it's 'XSalsa20-Poly1305'
    {
        const key = Buffer.alloc(sodiumNative.crypto_secretbox_KEYBYTES);
        r.symmetricEncryptAndAuthAlgos.push({name: "XSalsa20-Poly1305", source, impl: {
            ivNumBytes: sodiumNative.crypto_secretbox_NONCEBYTES,
            encryptAndAuth: (iv, input) => {
                const authTag = Buffer.allocUnsafe(sodiumNative.crypto_secretbox_MACBYTES);
                const cipherText = Buffer.allocUnsafe(input.length);
                sodiumNative.crypto_secretbox_detached(cipherText, authTag, input, iv, key);
                return [cipherText, authTag];
            },
            verifyDecrypt: (iv, [cipherText, authTag]) => {
                const plainText = Buffer.allocUnsafe(cipherText.length);
                const ok = sodiumNative.crypto_secretbox_open_detached(plainText, cipherText, authTag, iv, key);
                if (!ok) return null;
                return [plainText];
            },
        }});
    }

    // AEADs
    for (const [ident, name] of [
        ['chacha20poly1305_ietf', 'ChaCha20-Poly1305'],
        ['xchacha20poly1305_ietf', 'XChaCha20-Poly1305'],
    ]) {
        const key = Buffer.alloc(sodiumNative[`crypto_aead_${ident}_KEYBYTES`]);
        const authTagNumBytes = sodiumNative[`crypto_aead_${ident}_ABYTES`];
        const ivNumBytes = sodiumNative[`crypto_aead_${ident}_NPUBBYTES`];
        const encryptDetachedFn = sodiumNative[`crypto_aead_${ident}_encrypt_detached`];
        const decryptDetachedFn = sodiumNative[`crypto_aead_${ident}_decrypt_detached`];
        r.symmetricEncryptAndAuthAlgos.push({name, source, impl: {
            ivNumBytes,
            encryptAndAuth: (iv, input) => {
                const authTag = Buffer.allocUnsafe(authTagNumBytes);
                const cipherText = Buffer.allocUnsafe(input.length);
                encryptDetachedFn(cipherText, authTag, input, null, null, iv, key);
                return [cipherText, authTag];
            },
            verifyDecrypt: (iv, [cipherText, authTag]) => {
                const plainText = Buffer.allocUnsafe(cipherText.length);
                try {
                    decryptDetachedFn(plainText, null, cipherText, authTag, null, iv, key);
                } catch (err) {
                    return null;
                }
                return [plainText];
            },
        }});
    }


    // randombytes_buf
    r.randomAlgos.push({name: 'randombytes_buf', source, impl: sodiumNative.randombytes_buf});
};
