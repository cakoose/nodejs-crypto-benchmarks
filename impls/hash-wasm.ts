import * as hashWasm from 'hash-wasm';

import {Registry} from "../impl";

// For some reason, 'hash-wasm' doesn't export this type.
type IHasher = {
    init: () => IHasher;
    update: (data: Buffer) => IHasher;
    digest(outputType: 'binary'): Uint8Array;
};

export const register = async (r: Registry): Promise<void> => {
    r.packages.add('hash-wasm');

    const hashImpls: Array<[name: string, hasher: IHasher]> = [
        ['SHA-3-512', await hashWasm.createSHA3()],
        ['BLAKE2b', await hashWasm.createBLAKE2b()],
        ['BLAKE2s', await hashWasm.createBLAKE2s()],
        ['BLAKE3', await hashWasm.createBLAKE3()],
    ];
    for (const [name, hasher] of hashImpls) {
        r.hashAlgos.push({name, source: "NPM hash-wasm", impl: {streaming: handler => handler({
            construct: () => hasher.init(),
            update: (state, data) => {
                state.update(data);
            },
            final: state => state.digest('binary'),
        })}});
    }

    // These might be "cheating" because we're initializing the object with the key once,
    // instead of every time.
    const macImpls: Array<[name: string, hasher: IHasher]> = [
        ['BLAKE2b with key (cheating?)', await hashWasm.createBLAKE2b(undefined, r.macKey)],
        ['BLAKE2s with key (cheating?)', await hashWasm.createBLAKE2s(undefined, r.macKey)],
        ['BLAKE3 with key (cheating?)', await hashWasm.createBLAKE3(undefined, r.macKey)],
    ];
    for (const [name, hasher] of macImpls) {
        r.macAlgos.push({name, source: "NPM hash-wasm", impl: {streaming: handler => handler({
            construct: () => hasher.init(),
            update: (state, data) => {
                state.update(data);
            },
            final: state => state.digest('binary'),
        })}});
    }
};
