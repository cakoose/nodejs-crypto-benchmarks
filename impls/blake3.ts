import * as blake3 from 'blake3';

import {Registry} from "../impl";

export const register = async (r: Registry): Promise<void> => {
    r.packages.add('blake3');

    r.hashAlgos.push({name: 'BLAKE3', source: "NPM blake3", impl: {streaming: handler => handler({
        construct: () => blake3.createHash(),
        update: (state, data) => {
            state.update(data);
        },
        final: state => state.digest(),
    })}});
    r.macAlgos.push({name: `BLAKE3 with key`, source: "NPM blake2", impl: {streaming: handler => handler({
        construct: () => blake3.createKeyed(r.macKey),
        update: (state, data) => {
            state.update(data);
        },
        final: state => state.digest(),
    })}});
};
