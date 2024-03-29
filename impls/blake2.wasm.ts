import blake2Wasm from 'blake2.wasm';

import {Registry} from "../impl";

export const register = async (r: Registry): Promise<void> => {
    r.packages.add('blake2.wasm');

    await new Promise<void>(resolve => {
        blake2Wasm.ready(() => { resolve(); });
    });

    const macKey = r.macKey;
    for (const [variant, constructor, outputNumBytes] of [
        ['b', blake2Wasm.Blake2b, 64],
        ['s', blake2Wasm.Blake2s, 32],
    ] as Array<[string, any, number]>) {
        const name = `BLAKE2${variant}`;
        r.hashAlgos.push({name, source: "NPM blake2.wasm", impl: {streaming: handler => handler({
            construct: () => constructor(outputNumBytes),
            update: (state, data) => { state.update(data); },
            final: state => state.final(),
        })}, skipBigInputs: true});
        r.macAlgos.push({name: `${name} with key`, source: "NPM blake2.wasm", impl: {streaming: handler => handler({
            construct: () => constructor(outputNumBytes, macKey),
            update: (state, data) => { state.update(data); },
            final: state => state.final(),
        })}, skipBigInputs: true});
    }
};
