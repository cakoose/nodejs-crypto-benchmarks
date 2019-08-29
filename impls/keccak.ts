const keccakJs = require('keccak/js');
const keccakNative = require('keccak/bindings');

import {Registry} from "../impl";

export const register = async (r: Registry) => {
    r.packages.add('keccak');

    for (const [construct, implVariant] of [[keccakNative, 'native'], [keccakJs, 'JS']]) {
        const source = `NPM keccak (${implVariant})`;
        for (const numBits of [256, 512]) {
            const ident = `sha3-${numBits}`;
            r.hashAlgos.push({name: `SHA-3-${numBits}`, source, impl: {streaming: handler => handler({
                construct: () => construct(ident),
                update: (state, data) => { state.update(data); },
                final: state => state.digest(),
            })}});
        }
        for (const numBits of [128, 256]) {
            const outputNumBits = numBits * 2;
            const ident = `shake${numBits}`;
            r.hashAlgos.push({name: `SHAKE-${numBits}`, source, impl: {streaming: handler => handler({
                construct: () => construct(ident),
                update: (state, data) => { state.update(data); },
                final: state => state.squeeze(outputNumBits),
            })}});
        }
    }
};
