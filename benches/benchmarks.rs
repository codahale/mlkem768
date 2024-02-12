use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

fn key_gen(c: &mut Criterion) {
    c.bench_function("key-gen", |b| {
        let rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        b.iter_batched(|| rng.clone(), mlkem768::key_gen, BatchSize::SmallInput);
    });
}

fn encapsulate(c: &mut Criterion) {
    c.bench_function("encapsulate", |b| {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let (ek, _) = mlkem768::key_gen(&mut rng);
        b.iter_batched(
            || rng.clone(),
            |rng| mlkem768::encapsulate(&ek, rng),
            BatchSize::SmallInput,
        );
    });
}

fn decapsulate(c: &mut Criterion) {
    c.bench_function("decapsulate", |b| {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let (ek, dk) = mlkem768::key_gen(&mut rng);
        let (c, _) = mlkem768::encapsulate(&ek, &mut rng).expect("should encapsulate");
        b.iter(|| mlkem768::decapsulate(&dk, &c).expect("should decapsulate"));
    });
}

criterion_group!(benches, key_gen, encapsulate, decapsulate);
criterion_main!(benches);
