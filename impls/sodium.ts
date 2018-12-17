const sodium = require('sodium').api;

import {Registry} from "../impl";

export const register = async (r: Registry) => {
    const source = "NPM sodium";
    r.packages.push('sodium');
    const macKey = r.macKey;

    // crypto_hash
    for (const [name, ident] of [
        ["SHA-2-256", 'sha256'],
        ["SHA-2-512", 'sha512'],
    ]) {
        r.hashAlgos.push({
            name, source, impl: {
                oneShot: sodium[`crypto_hash_${ident}`],
                streaming: handler => handler({
                    construct: sodium[`crypto_hash_${ident}_init`],
                    update: sodium[`crypto_hash_${ident}_update`],
                    final: sodium[`crypto_hash_${ident}_final`],
                }),
            }
        });
    }

    // crypto_generichash_blake2b
    {
        const outputNumBytes = 64;
        const oneShot = sodium.crypto_generichash_blake2b;
        const construct = sodium.crypto_generichash_blake2b_init;
        const update = sodium.crypto_generichash_blake2b_update;
        const final = sodium.crypto_generichash_blake2b_final;
        r.hashAlgos.push({
            name: 'BLAKE2b', source, impl: {
                oneShot: input => oneShot(outputNumBytes, input, null),
                streaming: handler => handler({
                    construct: () => construct(null, outputNumBytes),
                    update,
                    final: state => final(state, outputNumBytes),
                }),
            }
        });
        r.macAlgos.push({
            name: `BLAKE2b with key`, source, impl: {
                oneShot: input => oneShot(outputNumBytes, input, macKey),
                streaming: handler => handler({
                    construct: () => construct(macKey, outputNumBytes),
                    update,
                    final: state => final(state, outputNumBytes),
                }),
            }
        });
    }

    // crypto_secretbox (not part of the function name, but it's 'XSalsa20-Poly1305'
    {
        const key = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES);
        r.symmetricEncryptAndAuthAlgos.push({
            name: "XSalsa20-Poly1305", source, impl: {
                ivNumBytes: sodium.crypto_secretbox_NONCEBYTES,
                encryptAndAuth: (iv, input) => {
                    const authTag = Buffer.allocUnsafe(sodium.crypto_secretbox_MACBYTES);
                    const cipherText = sodium.crypto_secretbox_detached(authTag, input, iv, key);
                    return [cipherText, authTag];
                },
                verifyDecrypt: (iv, [cipherText, authTag]) => {
                    const plainText = sodium.crypto_secretbox_open_detached(cipherText, authTag, iv, key);
                    return [plainText];
                },
            }
        });
    }

    // crypto_aead_aes256gcm
    {
        // NOTE: pre-"expanding" the key with crypto_aead_aes256gcm_beforenm doesn't seem to help significantly
        const key = Buffer.alloc(sodium.crypto_aead_aes256gcm_KEYBYTES);
        r.symmetricEncryptAndAuthAlgos.push({name: "AES-256-GCM", source, impl: {
            ivNumBytes: sodium.crypto_aead_aes256gcm_NPUBBYTES,
            encryptAndAuth: (iv, input) => {
                const {cipherText, mac: authTag} = sodium.crypto_aead_aes256gcm_encrypt_detached(input, null, iv, key);
                return [cipherText, authTag];
            },
            verifyDecrypt: (iv, [cipherText, authTag]) => {
                const plainText = sodium.crypto_aead_aes256gcm_decrypt_detached(cipherText, authTag, null, iv, key);
                return [plainText];
            },
        }});
    }

    // crypto_sign_ed25519
    {
        const seedBuffer = Buffer.alloc(sodium.crypto_sign_ed25519_SEEDBYTES);
        const {secretKey, publicKey} = sodium.crypto_sign_ed25519_seed_keypair(seedBuffer);
        const sign = sodium.crypto_sign_ed25519_detached;
        const verify = sodium.crypto_sign_ed25519_verify_detached;
        r.asymmetricSignAlgos.push({name: 'Ed25519 SHA-512', source, impl: {
            sign: message => sign(message, secretKey),
            verify: (signature, message) => (verify(signature, message, publicKey) !== undefined),
        }});
    }

    // randombytes_buf
    // TODO: Test with reused buffer?
    r.randomAlgos.push({name: 'randombytes_buf', source, impl: numBytes => {
        const b = Buffer.allocUnsafe(numBytes);
        sodium.randombytes_buf(b);
        return b;
    }});
};

