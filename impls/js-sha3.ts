import jsSha3 = require('js-sha3');

import {Registry} from "../impl";

const EMPTY_BUFFER = Buffer.alloc(0);

export const register = async (r: Registry) => {
    r.packages.push('js-sha3');

    const macKey = r.macKey;
    for (const [numBits, impl] of [
        [256, jsSha3.sha3_256],
        [512, jsSha3.sha3_512],
    ] as Array<[number, jsSha3.Hash]>) {
        r.hashAlgos.push({name: `SHA-3-${numBits}`, source: "NPM js-sha3", impl: {
            oneShot: input => impl.arrayBuffer(input),
            streaming: handler => handler({
                construct: () => impl.create(),
                update: (state, data) => { state.update(data); },
                final: state => state.arrayBuffer(),
            }),
        }});
    }
    for (const [numBits, shakeImpl, kmacImpl] of [
        [128, jsSha3.shake_128, jsSha3.kmac_128],
        [256, jsSha3.shake_256, jsSha3.kmac_256],
    ] as Array<[number, jsSha3.ShakeHash, jsSha3.KmacHash]>) {
        const outputNumBits = numBits * 2;
        r.hashAlgos.push({name: `SHAKE-${numBits}`, source: "NPM js-sha3", impl: {streaming: handler => handler({
            construct: () => shakeImpl.create(outputNumBits),
            update: (state, data) => { state.update(data); },
            final: state => state.arrayBuffer(),
        })}});
        r.macAlgos.push({name: `SHAKE/KMAC-${numBits}`, source: "NPM js-sha3", impl: {streaming: handler => handler({
            construct: () => kmacImpl.create(macKey, outputNumBits, EMPTY_BUFFER),
            update: (state, data) => { state.update(data); },
            final: state => state.arrayBuffer(),
        })}});
    }
};
