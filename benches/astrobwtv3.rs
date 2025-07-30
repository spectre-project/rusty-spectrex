// Public crates.
use criterion::{criterion_group, criterion_main, Criterion};
use rand::random;

// Private crates.
use spectrex::astrobwtv3;

fn astrobwtv3_bench(input: &[u8; 32]) {
    astrobwtv3::astrobwtv3_hash(input);
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("astrobwtv3_zeros", |b| b.iter(|| astrobwtv3_bench(&[0; 32])));

    c.bench_function("astrobwtv3_ones", |b| b.iter(|| astrobwtv3_bench(&[0xFF; 32])));

    c.bench_function("astrobwtv3_random", |b| {
        let random_data = random::<[u8; 32]>();
        b.iter(|| astrobwtv3_bench(&random_data))
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = criterion_benchmark
}
criterion_main!(benches);
