use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, criterion_group, criterion_main, measurement::WallTime,
};
use std::hint::black_box;
use zk_cred_longfellow::fields::{NttFieldElement, fieldp128::FieldP128, fieldp256_2::FieldP256_2};

fn benchmark_ntt<FE: NttFieldElement>(g: &mut BenchmarkGroup<WallTime>) {
    for size in [64, 256, 1024, 4096] {
        g.bench_function(BenchmarkId::new("ntt", size), |b| {
            let mut values = vec![FE::ONE; size];
            let omegas = FE::omegas();
            b.iter(|| FE::ntt_bit_reversed(black_box(&mut values), black_box(&omegas)));
        });
        g.bench_function(BenchmarkId::new("inverse_ntt", size), |b| {
            let mut values = vec![FE::ONE; size];
            let omega_inverses = FE::omega_inverses();
            let mut size_inverse = FE::ONE;
            for _ in 0..size.ilog2() {
                size_inverse *= FE::HALF;
            }
            assert_eq!(
                size_inverse * FE::from_u128(size.try_into().unwrap()),
                FE::ONE
            );
            b.iter(|| {
                FE::inverse_ntt_bit_reversed(
                    black_box(&mut values),
                    black_box(&omega_inverses),
                    black_box(size_inverse),
                )
            });
        });
    }
}

fn benchmark_ntt_fields(c: &mut Criterion) {
    let mut g = c.benchmark_group("fieldp128");
    benchmark_ntt::<FieldP128>(&mut g);
    g.finish();

    let mut g = c.benchmark_group("fieldp256_2");
    benchmark_ntt::<FieldP256_2>(&mut g);
    g.finish();
}

criterion_group!(benches, benchmark_ntt_fields);
criterion_main!(benches);
