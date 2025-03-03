// Public crates.
use criterion::{criterion_group, criterion_main, Criterion};

// Private crates.
use spectrex::astrobwtv3;

fn astrobwtv3_bench(input: &[u8; 32]) {
    astrobwtv3::astrobwtv3_hash(input);
}

fn criterion_benchmark(c: &mut Criterion) {
    let input: [u8; 32] = [0; 32];
    c.bench_function("astrobwtv3", |b| b.iter(|| astrobwtv3_bench(&input)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
