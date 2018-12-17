const sha3 = require('sha3');

import {Registry} from "../impl";

export const register = async (r: Registry) => {
    r.packages.push('sha3');

    for (const numBits of [256, 512]) {
        r.hashAlgos.push({name: `SHA-3-${numBits}`, source: "NPM sha3", impl: {streaming: handler => handler({
            construct: () => sha3.SHA3(numBits),
            update: (state, data) => { state.update(data); },
            final: state => state.digest(),
        })}, skipBigInputs: true});  // this module is slow
    }
};
