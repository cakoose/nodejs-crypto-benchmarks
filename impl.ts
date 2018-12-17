export type HashImpl = {
    oneShot?: (input: Buffer) => Buffer | ArrayBuffer,
    streaming: (handler: StreamingHashHandler) => void,
};

export type StreamingHashImpl<State> = {
    construct: () => State,
    update: (state: State, data: Buffer) => void,
    final: (state: State) => Buffer | ArrayBuffer,
};

// A wrapper so we can use 'State' as an existentially quantified type.
export type StreamingHashHandler = <State>(digester: StreamingHashImpl<State>) => void;

export type AsymmetricSignImpl = {
    sign: (input: Buffer) => Buffer,
    verify: (signature: Buffer, input: Buffer) => boolean,
};

export type SymmetricEncryptAndAuthImpl = {
    ivNumBytes: number,
    encryptAndAuth: (iv: Buffer, plainText: Buffer) => Array<Buffer>,  /// cipherText, authTag, etc
    verifyDecrypt: (iv: Buffer, chunks: Array<Buffer>) => Array<Buffer> | null,
};

export type RandomImpl = (numBytes: number) => Buffer;

export type Algo<Impl> = {
    name: string,
    source: string,
    impl: Impl,
    // To reduce the number of things we have to run, we don't run some implementations on large inputs.
    // 1. Some implementations are slow.  They're included just so people can see how slow they
    //    are, but let's not waste time running them on large inputs.
    // 2. Some implementations are just slight variations on other ones, where the difference
    //    only matters for small inputs.  For example, we might have variations where we
    //    pre-allocate some of the buffers.  This only makes a significant difference for
    //    small inputs.
    skipBigInputs?: true,
};

export type Registry = {
    packages: Array<string>,
    hashAlgos: Array<Algo<HashImpl>>,
    macAlgos: Array<Algo<HashImpl>>,
    asymmetricSignAlgos: Array<Algo<AsymmetricSignImpl>>,
    symmetricEncryptAndAuthAlgos: Array<Algo<SymmetricEncryptAndAuthImpl>>,
    randomAlgos: Array<Algo<RandomImpl>>,
    macKey: Buffer,
};
