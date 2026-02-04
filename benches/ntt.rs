use criterion::{BenchmarkGroup, BenchmarkId, Criterion, criterion_group, measurement::WallTime};
use std::hint::black_box;
use zk_cred_longfellow::fields::{NttFieldElement, fieldp128::FieldP128, fieldp256_2::FieldP256_2};

fn benchmark_ntt<FE: NttFieldElement>(g: &mut BenchmarkGroup<WallTime>) {
    for size in [64, 256, 1024, 4096] {
        g.bench_function(BenchmarkId::new("ntt", size), |b| {
            let mut values = vec![FE::ONE; size];
            b.iter(|| FE::ntt_bit_reversed(black_box(&mut values)));
        });
        g.bench_function(BenchmarkId::new("inverse_ntt", size), |b| {
            let mut values = vec![FE::ONE; size];
            b.iter(|| FE::scaled_inverse_ntt_bit_reversed(black_box(&mut values)));
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

fn main() {
    let git_version = git_version::git_version!(fallback = "unknown");
    println!("Git revision: {git_version}");
    println!();

    benches();
    Criterion::default().configure_from_args().final_summary();
}
