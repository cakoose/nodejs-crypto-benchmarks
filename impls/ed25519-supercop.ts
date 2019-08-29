const ed25519Supercop = require('ed25519-supercop');

import {Registry} from "../impl";

export const register = async (r: Registry) => {
    r.packages.add('ed25519-supercop');

    const {secretKey, publicKey} = ed25519Supercop.createKeyPair(Buffer.alloc(32));
    r.asymmetricSignAlgos.push({name: "Ed25519 SHA-512", source: "NPM ed25519-supercop", impl: {
        sign: message => ed25519Supercop.sign(message, publicKey, secretKey),
        verify: (signature, message) => ed25519Supercop.verify(signature, message, publicKey),
    }});
};
