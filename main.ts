require('source-map-support').install();  // eslint-disable-line @typescript-eslint/no-var-requires

import assert from 'assert';
import * as Benchmark from 'benchmark';
import * as os from 'os';
import * as argparse from 'argparse';

import {Algo, HashImpl, Registry} from './impl';

import {register as registerBlake2} from './impls/blake2';
import {register as registerBlake2Wasm} from './impls/blake2.wasm';
import {register as registerBlake3} from './impls/blake3';
import {register as registerChachaNative} from './impls/chacha-native';
import {register as registerEd25519Supercop} from './impls/ed25519-supercop';
import {register as registerJsSha3} from './impls/js-sha3';
import {register as registerJssha} from './impls/jssha';
import {register as registerKeccak} from './impls/keccak';
import {register as registerNodeCrypto} from './impls/node-crypto';
import {register as registerSha3} from './impls/sha3';
import {register as registerSodium} from './impls/sodium';
import {register as registerSodiumNative} from './impls/sodium-native';

const BIG_INPUT_THRESHOLD = 4 * 1024;

async function mainAsync(progName: string, args: Array<string>) {
    const {filters, test} = parseArgs(progName, args);
    const passesFilter = (name: string) => {
        if (filters.length === 0) {
            return true;
        }
        for (const filter of filters) {
            if (filter.regex.test(name)) {
                return filter.include;
            }
        }
        // If the first filter is an '--include', then something that matches no
        // filters will be excluded.  If the first filter is an '--exclude', then
        // something that matches no filters will be included.
        return !filters[0].include;
    };

    const r: Registry = {
        packages: new Set(),
        hashAlgos: [],
        macAlgos: [],
        asymmetricSignAlgos: [],
        symmetricEncryptAndAuthAlgos: [],
        randomAlgos: [],
        macKey: Buffer.alloc(32),
    };

    await registerBlake2(r);
    await registerBlake2Wasm(r);
    await registerBlake3(r);
    await registerChachaNative(r);
    await registerEd25519Supercop(r);
    await registerJsSha3(r);
    await registerJssha(r);
    await registerKeccak(r);
    await registerNodeCrypto(r);
    await registerSha3(r);
    await registerSodium(r);
    await registerSodiumNative(r);

    r.hashAlgos.sort(compareAlgos);
    r.macAlgos.sort(compareAlgos);
    r.asymmetricSignAlgos.sort(compareAlgos);
    r.symmetricEncryptAndAuthAlgos.sort(compareAlgos);

    const oneShotInputs = makeOneShotInputs();
    const streamingInputs = makeStreamingInputs();

    printSystemInformation(r.packages);
    console.log();

    console.log("Reported value is \"ns per input byte\".");
    console.log("Reported value is the fastest of multiple test samples, except for random number");
    console.log("generation, where we report the mean.");
    console.log();

    const runHashAlgos = (algos: Array<Algo<HashImpl>>) => {
        for (const [inputDescription, inputNumBytes, input] of oneShotInputs) {
            const suite = createSuite(test, inputNumBytes, `${inputDescription}`);
            for (const {name, source, impl, skipBigInputs} of algos) {
                if (skipBigInputs === true && inputNumBytes > BIG_INPUT_THRESHOLD) continue;
                const fullName = `${name}, ${source}`;
                if (!passesFilter(fullName)) continue;
                const {oneShot, streaming} = impl;
                if (oneShot !== undefined) {
                    suite.add(fullName, () => {
                        oneShot(input);
                    });
                } else {
                    // If there's no 'oneShot', just use 'streaming'.
                    streaming(({construct, update, final}) => {
                        suite.add(fullName, () => {
                            const state = construct();
                            update(state, input);
                            final(state);
                        });
                    });
                }
            }
            suite.run();
            console.log();
        }
        for (const [inputDescription, inputNumBytes, inputChunks] of streamingInputs) {
            const suite = createSuite(test, inputNumBytes, inputDescription);
            for (const {name, source, impl, skipBigInputs} of algos) {
                if (skipBigInputs === true && inputNumBytes > BIG_INPUT_THRESHOLD) continue;
                const fullName = `${name}, ${source}`;
                if (!passesFilter(fullName)) continue;
                impl.streaming(({construct, update, final}) => {
                    suite.add(fullName, () => {
                        const state = construct();
                        for (const chunk of inputChunks) {
                            update(state, chunk);
                        }
                        final(state);
                    });
                });
            }
            suite.run();
            console.log();
        }
    };

    console.log("------------------------------------------------");
    console.log("Hash");
    console.log();
    runHashAlgos(r.hashAlgos);

    console.log("------------------------------------------------");
    console.log(`Hash-based MAC, ${r.macKey.length}-byte key`);
    console.log();
    runHashAlgos(r.macAlgos);

    console.log("------------------------------------------------");
    console.log("Symmetric Encrypt+Authenticate");
    console.log();
    for (const [inputDescription, inputNumBytes, input] of oneShotInputs) {
        const encryptAndAuthCounterIvSuite = createSuite(test, inputNumBytes, `${inputDescription} Encrypt+Sign (excluding IV generation)`);
        const verifyDecryptSuite = createSuite(test, inputNumBytes, `${inputDescription} Verify+Decrypt`);
        for (const {name, source, impl, skipBigInputs} of r.symmetricEncryptAndAuthAlgos) {
            if (skipBigInputs === true && inputNumBytes > BIG_INPUT_THRESHOLD) continue;
            const {ivNumBytes, encryptAndAuth, verifyDecrypt} = impl;
            const fullName = `${name}, ${source}`;
            if (!passesFilter(fullName)) continue;
            encryptAndAuthCounterIvSuite.add(fullName, () => {
                encryptAndAuth(Buffer.alloc(ivNumBytes), input);
            });
            const iv = Buffer.alloc(ivNumBytes);
            const chunks = encryptAndAuth(iv, input);
            verifyDecryptSuite.add(fullName, () => {
                const data = verifyDecrypt(iv, chunks);
                assert(data !== null);
            });
        }
        encryptAndAuthCounterIvSuite.run();
        verifyDecryptSuite.run();
        console.log();
    }

    console.log("------------------------------------------------");
    console.log("Asymmetric Sign");
    console.log();
    for (const [inputDescription, inputNumBytes, input] of oneShotInputs) {
        const signSuite = createSuite(test, inputNumBytes, `${inputDescription} Sign`);
        const verifySuite = createSuite(test, inputNumBytes, `${inputDescription} Verify`);
        for (const {name, source, impl, skipBigInputs} of r.asymmetricSignAlgos) {
            if (skipBigInputs === true && inputNumBytes > BIG_INPUT_THRESHOLD) continue;
            const {sign, verify} = impl;
            const fullName = `${name}, ${source}`;
            if (!passesFilter(fullName)) continue;
            signSuite.add(fullName, () => {
                sign(input);
            });
            const signature = sign(input);
            verifySuite.add(fullName, () => {
                verify(signature, input);
            });
        }
        signSuite.run();
        verifySuite.run();
        console.log();
    }

    console.log("------------------------------------------------");
    console.log("Generate Random Bytes (into existing Buffer)");
    console.log();
    for (const numBytes of [16, 32, 64, 1024]) {
        const buffer = Buffer.alloc(numBytes);
        const suite = createSuiteReportMean(test, numBytes, `${numBytes} bytes`);
        for (const {name, source, impl} of r.randomAlgos) {
            const fullName = `${name}, ${source}`;
            if (!passesFilter(fullName)) continue;
            suite.add(fullName, () => {
                impl(buffer);
            });
        }
        suite.run();
        console.log();
    }
}

// Has an interface similar to Benchmark.Suite, but just runs the code twice.
// We swap this in when we just want to test that the code works without running
// the full benchmark.
class TestSuite {
    private name: string;
    private readonly fns: Array<[string, () => void]>;
    constructor(name: string) {
        this.name = name;
        this.fns = [];
    }
    add(name: string, fn: () => void) {
        this.fns.push([name, fn]);
    }
    run() {
        for (const [name, fn] of this.fns) {
            console.log(name);
            fn();
            fn();
        }
    }
}

function makeOneShotInputs(): Array<[string, number, Buffer]> {
    const r: Array<[string, number, Buffer]> = [];
    for (const [description, numBytes] of [
        ['128B', 128],
        ['4k', 4 * 1024],
        ['128k', 128 * 1024],
        ['4M', 4 * 1024 * 1024],
    ] as Array<[string, number]>) {
        r.push([description, numBytes, createBufferWithOwnArrayBuffer(numBytes)]);
    }
    return r;
}

function makeStreamingInputs(): Array<[string, number, Array<Buffer>]> {
    return [
        ['4M streaming (4k chunks)', 4 * 1024 * 1024, Array(1024).fill(createBufferWithOwnArrayBuffer(4 * 1024))],
    ]
}

function createBufferWithOwnArrayBuffer(numBytes: number): Buffer {
    // NOTE: Explicitly allocate the underlying ArrayBuffer so the Buffer's `.buffer` property is
    // the right size.  Without this, multiple Buffer objects might just be views into a section
    // of a larger ArrayBuffer.  We rely on the `.buffer` being the right size when testing
    // libraries that only accept an ArrayBuffer.
    const ab = new ArrayBuffer(numBytes);
    const b = Buffer.from(ab);
    assert(b.length === ab.byteLength);
    return b;
}

function printSystemInformation(packages: Iterable<string>) {
    const cpuCountsByModel = new Map();
    for (const cpu of os.cpus()) {
        if (cpuCountsByModel.has(cpu.model)) {
            cpuCountsByModel.set(cpu.model, cpuCountsByModel.get(cpu.model) + 1);
        } else {
            cpuCountsByModel.set(cpu.model, 1);
        }
    }
    for (const [model, count] of cpuCountsByModel) {
        console.log(`CPU      ${count}x ${model}`);
    }
    console.log(`Node     ${process.versions.node}`);
    console.log(`V8       ${process.versions.v8}`);
    console.log(`OpenSSL  ${process.versions.openssl}`);
    console.log(`OS       ${os.platform()}, ${os.release()}`);
    console.log(`NPM `);
    for (const pkg of packages) {
        const version = require(`${pkg}/package.json`).version;  // eslint-disable-line @typescript-eslint/no-var-requires
        console.log(`    ${pkg} ${version}`);
    }
}

function compareAlgos<T>(a: Algo<T>, b: Algo<T>): -1 | 0 | 1 {
    const cmp = compareStrings(a.name, b.name);
    if (cmp !== 0) {
        return cmp;
    }
    return compareStrings(a.source, b.source);
}

function compareStrings(a: string, b: string): -1 | 0 | 1 {
    if (a < b) {
        return -1;
    } else if (a > b) {
        return 1;
    } else {
        return 0;
    }
}

const createSuiteReportMean = createSuiteHelper(true, targetStats => targetStats.mean);
const createSuite = createSuiteHelper(false, targetStats => Math.min(...targetStats.sample));

function createSuiteHelper(includeRme: boolean, getSeconds: (targetStats: any) => number) {
    return (test: boolean, numBytes: number, name: string) => {
        if (test) {
            return new TestSuite(name);
        }
        return new Benchmark.Suite(name, {
            onStart() {
                console.log(name);
            },
            onCycle(evt: Benchmark.Event) {
                // TODO: Show deviation?
                const target = (evt.target as any);  // TODO: Improve NPM package '@types/benchmark' and remove 'any'
                // Using the minimum time because that's probably what we care about in these
                // allocation-free pure-CPU microbenchmarks.  TODO: Is that an ok thing to do?
                const seconds = getSeconds(target.stats);
                const ns = Math.round(seconds * 1_000_000_000);
                const nsPerByte = ns / numBytes;
                const rmeString = includeRme ? ` ±${target.stats.rme.toFixed(0).padStart(2)}%` : '';
                console.log(`${nsPerByte.toFixed(2).padStart(8)}${rmeString}  ${target.name}`);
            },
            onError(evt: Benchmark.Event) {
                throw (evt.target as any).error;
            },
            onAbort() {
                throw new Error('aborted benchmark suite');
            },
        });
    }
}

type Filter = {
    include: boolean,
    regex: RegExp,
}

function parseArgs(progName: string, args: Array<string>) {
    const parser = new argparse.ArgumentParser({
        prog: progName,
        addHelp: true,
        description: 'nodejs crypto benchmark',
    });
    const filters: Array<Filter> = [];
    const makeFilterAction = (include: boolean) => {
        class FilterAction extends argparse.Action {
            call(parser: any, namespace: any, values: Array<string>, optionString: any) {
                console.log('action', JSON.stringify({values, optionString, dest: this.dest}));
                let regex;
                try {
                    regex = new RegExp(values[0]);
                } catch (err) {
                    console.log(`Error: invalid regular expression: ${JSON.stringify(args[0])}: ${err}`);
                    throw process.exit(1);
                }
                filters.push({include, regex});
            }
        }
        return FilterAction;
    };

    parser.addArgument('--include', {
        nargs: '*',
        action: (makeFilterAction(true) as any),
        help: "Regex of algorithms to include",
    });
    parser.addArgument('--exclude', {
        nargs: '*',
        action: (makeFilterAction(false) as any),
        help: "Regex of algorithms to exclude",
    });
    parser.addArgument('--test', {
        defaultValue: false,
        action: 'storeTrue',
        help: "Just test that the benchmarks work",
    });
    const parsed = parser.parseArgs(args);
    return {
        filters,
        test: parsed.test,
    };
}

if (require.main === module) {
    mainAsync(process.argv[1], process.argv.slice(2))
        .catch(err => { console.error(err); });
}
