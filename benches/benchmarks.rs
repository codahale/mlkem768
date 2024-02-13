use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use mlkem768::xwing;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

fn key_gen(c: &mut Criterion) {
    let mut g = c.benchmark_group("key_gen");
    g.bench_function("ml-kem-768", |b| {
        let rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        b.iter_batched(|| rng.clone(), mlkem768::key_gen, BatchSize::SmallInput);
    });
    g.bench_function("x-wing", |b| {
        let rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        b.iter_batched(|| rng.clone(), xwing::key_gen, BatchSize::SmallInput);
    });
    g.finish();
}

fn encapsulate(c: &mut Criterion) {
    let mut g = c.benchmark_group("encapsulate");
    g.bench_function("ml-kem-768", |b| {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let (ek, _) = mlkem768::key_gen(&mut rng);
        b.iter_batched(
            || rng.clone(),
            |rng| mlkem768::encapsulate(&ek, rng),
            BatchSize::SmallInput,
        );
    });
    g.bench_function("x-wing", |b| {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let (ek, _) = xwing::key_gen(&mut rng);
        b.iter_batched(|| rng.clone(), |rng| xwing::encapsulate(&ek, rng), BatchSize::SmallInput);
    });
    g.finish();
}

fn decapsulate(c: &mut Criterion) {
    let mut g = c.benchmark_group("decapsulate");
    g.bench_function("ml-kem-768", |b| {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let (ek, dk) = mlkem768::key_gen(&mut rng);
        let (c, _) = mlkem768::encapsulate(&ek, &mut rng).expect("should encapsulate");
        b.iter(|| mlkem768::decapsulate(&dk, &c).expect("should decapsulate"));
    });
    g.bench_function("x-wing", |b| {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let (ek, dk) = xwing::key_gen(&mut rng);
        let (c, _) = xwing::encapsulate(&ek, &mut rng).expect("should encapsulate");
        b.iter(|| xwing::decapsulate(&dk, &c).expect("should decapsulate"));
    });
    g.finish();
}

criterion_group!(benches, key_gen, encapsulate, decapsulate);
criterion_main!(benches);
