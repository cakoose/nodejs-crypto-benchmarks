# Node.js Crypto Benchmarks (BETA)

Measures the execution time of a few crypto algorithm implementations on Node.js.

This is marked "beta" because I'm not an expert in Node.js, benchmarking, or using crypto algorithms; there's a good chance I made a mistake somewhere.  Maybe once more people have looked over the code I'll remove the "beta" tag.

As with all benchmarks, **be careful when interpreting the results!**
- The exact Node.js version, OpenSSL version, and NPM package versions can make a big difference.
- The exact CPU you're running on can make a big difference, especially for native libraries, which may use entirely different code for different CPUs.
- This benchmark uses the library functions in a specific way (e.g. with a `Buffer`).  Using them differently will give different results.
- This benchmark runs each algorithm implementation in a tight loop and measures total running time.  It doesn't measure cache footprint, JIT time, and a bunch of other things that affect the overall performance of a real-world program.

## Running

Clone this repo, then run:

```
$ yarn install --frozen-lockfile
$ yarn run bench [regex]
```

## Results

[MacBook Pro 15" 2017, Intel Core i7](results/MacBook-Pro-15-2017-Intel-Core-i7.md)
