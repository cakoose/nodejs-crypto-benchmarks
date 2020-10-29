import * as sha3 from 'sha3';

import {Registry} from "../impl";

export const register = async (r: Registry): Promise<void> => {
    r.packages.add('sha3');

    for (const [name, construct] of [
        ['SHA-3-256', () => new sha3.SHA3(256)],
        ['SHA-3-512', () => new sha3.SHA3(512)],
        ['SHAKE-128', () => new sha3.SHAKE(128 as any)], // https://github.com/phusion/node-sha3/issues/90
        ['SHAKE-256', () => new sha3.SHAKE(256)],
    ] as Array<[string, () => sha3.SHA3]>) {
        r.hashAlgos.push({name, source: "NPM sha3", impl: {streaming: handler => handler({
            construct,
            update: (state, data) => { state.update(data); },
            final: state => state.digest(),
        })}, skipBigInputs: true}); // this module is slow
    }
};
