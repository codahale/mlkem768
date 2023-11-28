use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

#[divan::bench]
fn key_gen(bencher: divan::Bencher) {
    bencher.with_inputs(|| ChaChaRng::seed_from_u64(0xDEADBEEF)).bench_values(mlkem768::key_gen)
}

#[divan::bench]
fn encapsulate(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let (ek, _) = mlkem768::key_gen(&mut rng);
            (rng, ek)
        })
        .bench_values(|(mut rng, ek)| mlkem768::encapsulate(&ek, &mut rng))
}

#[divan::bench]
fn decapsulate(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let (ek, dk) = mlkem768::key_gen(&mut rng);
            let (c, _) = mlkem768::encapsulate(&ek, &mut rng).expect("should encapsulate");
            (dk, c)
        })
        .bench_refs(|(dk, c)| mlkem768::decapsulate(dk, c))
}

fn main() {
    divan::main()
}
