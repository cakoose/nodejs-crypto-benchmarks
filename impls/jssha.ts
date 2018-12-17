import jssha = require("jssha");

import {Registry} from "../impl";

export const register = async (r: Registry) => {
    r.packages.push('jssha');

    // NPM jssha
    for (const [name, ident] of [
        ['SHA-1 (insecure)', 'SHA-1'],
        ['SHA-2-256', 'SHA-256'],
        ['SHA-2-512', 'SHA-512'],
        ['SHA-3-256', 'SHA3-256'],
        ['SHA-3-512', 'SHA3-512'],
    ]) {
        r.hashAlgos.push({name, source: "NPM jssha", impl: {streaming: handler => handler({
            construct: () => new jssha(ident, 'ARRAYBUFFER'),
            update: (state, data) => { state.update(data.buffer); },
            final: state => state.getHash('ARRAYBUFFER'),
        })}, skipBigInputs: true});  // this module is slow
        // NOTE: Intentionally not including HMAC to save time and reduce the size of the results.
    }
    for (const numBits of [128, 256]) {
        const outputNumBits = numBits * 2;
        const name = `SHAKE-${numBits}`;
        const ident = `SHAKE${numBits}`;
        r.hashAlgos.push({name, source: 'NPM jssha', impl: {streaming: handler => handler({
            construct: () => new jssha(ident, 'ARRAYBUFFER'),
            update: (state, data) => { state.update(data); },
            final: state => state.getHash('ARRAYBUFFER', {shakeLen: outputNumBits}),
        })}, skipBigInputs: true});  // this module is slow
    }
};
