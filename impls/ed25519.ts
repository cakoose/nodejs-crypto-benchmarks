const ed25519 = require('ed25519');

import {Registry} from "../impl";

export const register = async (r: Registry) => {
    r.packages.add('ed25519');

    const {privateKey, publicKey} = ed25519.MakeKeypair(Buffer.alloc(32));
    r.asymmetricSignAlgos.push({name: "Ed25519 SHA-512", source: "NPM ed25519", impl: {
        sign: message => ed25519.Sign(message, privateKey),
        verify: (signature, message) => ed25519.Verify(message, signature, publicKey),
    }});
};
