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
$ yarn install
$ yarn run build  # or: yarn run watch
$ yarn run bench [--include <regex>] [--exclude <regex>] [--test]
```

## Results

2026-01-20:
- GCP c4-standard-4: [Node 24.13.0](results/2026-01-20-Node-24.13.0-GCP-c4-standard-4.txt).
- GCP c4a-standard-4: [Node 24.13.0](results/2026-01-20-Node-24.13.0-GCP-c4a-standard-4.txt).

2024-03-15:
- GCP n2-standard-4: [Node 20.11.1](results/2024-03-15-Node-20.11.1-GCP-n2-standard-4.txt).

2020-10-20:
- GCP e2-standard-4: [Node 14.14.0](results/2020-10-29-Node-14.14.0-GCP-e2-standard-4.txt).

2019-09-04:
- MacBook Pro 15" 2017: [Node 8.15.0](results/2019-09-04-Node-8.15.0-MacBook-Pro-15-2017.txt), [Node 11.15.0](results/2019-09-04-Node-11.15.0-MacBook-Pro-15-2017.txt).

## Running benchmarks on GCP or AWS

Create new VM instance:
- Two physical cores (which typically corresponds to 4 "vCPUs")
- The latest Ubuntu LTS.

```
# SSH to machine.

sudo apt-get update
sudo apt-get install git libtool automake gcc g++ make tmux vim
curl https://get.volta.sh | bash

# Exit and re-SSH to pull in ~/.bashrc updates

git clone https://github.com/cakoose/nodejs-crypto-benchmarks.git
cd nodejs-crypto-benchmarks
yarn install
yarn run build

# Start a 'tmux' session so the benchmark continues running even if you disconnect

yarn run bench | tee results.txt
```

## Explanation for non-obvious packages

- `microtime`: The `benchmark` package says to install that for higher-precision timing on Node.js

