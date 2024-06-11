# SpectreX

[![Crates.io](https://img.shields.io/crates/v/spectrex.svg)](https://crates.io/crates/spectrex)
[![GitHub license](https://img.shields.io/github/license/spectre-project/rusty-spectrex.svg)](https://github.com/spectre-project/rusty-spectrex/blob/main/LICENSE)

SpectreX is a versatile CPU mining algorithm library used by the
[Spectre On Rust](https://github.com/spectre-project/rusty-spectre)
full-node daemon.

## Overview

SpectreX features the [AstroBWTv3](https://github.com/deroproject/derohe/tree/main/astrobwt/astrobwtv3)
algorithm, a proof-of-work (PoW) system based on the Burrows-Wheeler
transform (BWT). This version of AstroBWTv3 is completely written in
Rust, without any external C dependencies, relying solely on various
Rust crates.

## Hashing Function

The proof-of-work calculation involves a series of sequential hashing
functions to form the final hash:

* Step 1: Calculate sha256 of the input data.
* Step 2: Expand data using Salsa20.
* Step 3: Encrypt data with RC4 based on the output from step 2.
* Step 4: Compute an initial FNV-1a hash of the result from step 3.
* Step 5: Apply a branchy loop using RC4 stream encryption on the data from step 4.
* Step 6: Build and sort a Suffix Array with the result from step 5.
* Step 7: Calculate the final sha256 of the data from step 6.

## Improvements

The original algorithm utilized the [SA-IS](https://en.wikipedia.org/wiki/Suffix_array)
sorting algorithm. There exists an enhanced one with [SACA-K](https://www.sciencedirect.com/science/article/abs/pii/S0020019016301375)
for induced sorting, improving the linear-time complexity to be
in-place for constant alphabets. However, this remains a single-core
variant. Our AstroBWTv3 implementation has switched to
[pSACAK](https://ieeexplore.ieee.org/document/8371211), a fast
linear-time, in-place parallel algorithm that leverages multi-core
machines. It is fully compatible with the original AstroBWTv3 Suffix
Array.

There are still numerous opportunities to enhance the computation of
AstroBWTv3 hashes, including:

* Replacing most steps with highly optimized inline assembler code on
  CPU.
* Partitioning the Suffix Array and offloading sorting to GPUs to
  significantly boost performance.

We encourage developers to optimize individual calculation steps to
evolve the algorithm over time and mature the codebase.

## Usage

To include SpectreX in your project dependencies, just run the command
`cargo add spectrex`. Here's a straightforward example:

```rust
use spectrex::astrobwtv3;

fn main() {
    let hash_in: [u8; 32] = [88, 101, 183, 41, 212, 156, 190, 48, 230, 97, 94, 105, 177, 86, 88, 84, 60, 239, 203, 124, 63, 32, 160, 222, 34, 141, 50, 108, 138, 16, 90, 230];
    let hash_out = astrobwtv3::astrobwtv3_hash(&hash_in);
    println!("hash_out: {:?}", hash_out);
}
```

## Tests

Below is a basic computation test designed to ensure the accuracy of
computed hashes across various byte orders. You can execute it using
`cargo test`, and upon successful completion, it will display the
following output:

```
running 1 test
test astrobwtv3_hash_10 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.54s
```

## Benchmarks

Included is a simple computation benchmark using [Criterion](https://github.com/bheisler/criterion.rs).
This benchmark helps verify any performance improvements or
degradations if any calculation steps have been modified. You can run
it using `cargo bench`, and it will return the following results:

```
astrobwtv3              time:   [8.8912 ms 9.0648 ms 9.2387 ms]
                        change: [-7.8592% -4.5050% -1.1622%] (p = 0.01 < 0.05)
                        Performance has improved.
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild
```
