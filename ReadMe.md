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
$ yarn run bench [--include <regex>] [--exclude <regex>] [--test]
```

## Results

- MacBook Pro 15" 2017: [Node 8.15.0](results/Node-8.15.0-MacBook-Pro-15-2017.txt), [Node 11.15.0](results/Node-11.15.0-MacBook-Pro-15-2017.txt)

## Running benchmarks on GCP or AWS

Create new VM instance: at least 4 vCPUs (usually means 2 physical cores) and the latest Ubuntu LTS.

```
# SSH into machine.

sudo apt-get update
sudo apt-get install git libtool automake gcc g++ make

git clone https://github.com/nodenv/nodenv.git ~/.nodenv
cd ~/.nodenv && src/configure && make -C src
echo 'eval "$(nodenv init -)"' >> ~/.bashrc
export PATH="$HOME/.nodenv/bin:$PATH

# Exit and re-SSH to pull in ~/.bashrc updates

mkdir -p "$(nodenv root)"/plugins
git clone https://github.com/nodenv/node-build.git "$(nodenv root)"/plugins/node-build

nodenv install 14.14.0
nodenv global 14.14.0
npm install -g yarn
nodenv rehash

git clone https://github.com/cakoose/nodejs-crypto-benchmarks.git
cd nodejs-crypto-benchmarks
yarn install
yarn run build
yarn run bench --test
yarn run bench | tee results.txt
```
