const blake2 = require('blake2');

import {Registry} from "../impl";

export const register = async (r: Registry) => {
    r.packages.add('blake2');

    const macKey = r.macKey;
    for (const variant of ['b', 'bp', 's', 'sp']) {
        const name = `BLAKE2${variant}`;
        const ident = `blake2${variant}`;
        r.hashAlgos.push({name, source: "NPM blake2", impl: {streaming: handler => handler({
            construct: () => blake2.createHash(ident),
            update: (state, data) => {
                state.update(data);
            },
            final: state => state.digest(),
        })}});
        r.macAlgos.push({name: `${name} with key`, source: "NPM blake2", impl: {streaming: handler => handler({
            construct: () => blake2.createKeyedHash(ident, macKey),
            update: (state, data) => {
                state.update(data);
            },
            final: state => state.digest(),
        })}});
    }
};
