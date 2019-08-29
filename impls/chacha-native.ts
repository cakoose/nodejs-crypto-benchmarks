import assert = require('assert');
const chachaNative = require('chacha-native');

import {Registry} from "../impl";

const EMPTY_BUFFER = Buffer.alloc(0);

export const register = async (r: Registry) => {
    r.packages.add('chacha-native');

    const key = Buffer.alloc(32);
    r.symmetricEncryptAndAuthAlgos.push({
        name: "ChaCha20-Poly1305", source: "NPM chacha-native", impl: {
            ivNumBytes: 12,
            encryptAndAuth: (iv, input) => {
                const cipher = chachaNative.createCipher(key, iv);
                cipher.setAAD(EMPTY_BUFFER);
                const cipherText = cipher.update(input);
                const cipherTextFinal = cipher.final();
                assert(cipherTextFinal.length === 0);  // If not empty, we would have to append to 'cipherText'.
                const authTag = cipher.getAuthTag();
                return [cipherText, authTag];
            },
            verifyDecrypt: (iv, [cipherText, authTag]) => {
                const decipher = chachaNative.createDecipher(key, iv);
                decipher.setAAD(EMPTY_BUFFER);
                decipher.setAuthTag(authTag);
                const plainText = decipher.update(cipherText);
                // TODO: try/catch
                const plainTextFinal = decipher.final();
                assert(plainTextFinal.length === 0);
                return [plainText];
            },
        },
    });
};
