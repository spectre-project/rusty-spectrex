// Public crates.
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;

// Private crates.
use spectrex::astrobwtv3;

fn astrobwtv3_bench() {
    let input: [u8; 32] = rand::random();
    astrobwtv3::astrobwtv3_hash(&input);
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("astrobwtv3", |b| b.iter(|| astrobwtv3_bench()));
}

criterion_group!(
    benches,
    criterion_benchmark);
criterion_main!(
    benches
);
