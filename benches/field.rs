use criterion::{
    BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::WallTime,
};
use std::hint::black_box;
use zk_cred_longfellow::fields::{
    FieldElement, ProofFieldElement, field2_128::Field2_128, fieldp128::FieldP128,
    fieldp256::FieldP256, fieldp256_2::FieldP256_2,
};

fn benchmark_field<FE: FieldElement>(g: &mut BenchmarkGroup<WallTime>) {
    g.bench_function("add", |b| {
        b.iter(|| black_box(FE::ZERO) + black_box(FE::ZERO))
    });

    g.bench_function("subtract", |b| {
        b.iter(|| black_box(FE::ZERO) - black_box(FE::ZERO))
    });

    g.bench_function("multiply", |b| {
        b.iter(|| black_box(FE::ZERO) * black_box(FE::ZERO))
    });

    g.bench_function("square", |b| b.iter(|| black_box(FE::ZERO).square()));
}

fn benchmark_all_fields(c: &mut Criterion) {
    let mut g = c.benchmark_group("fieldp128");
    benchmark_field::<FieldP128>(&mut g);
    g.finish();

    let mut g = c.benchmark_group("fieldp256");
    benchmark_field::<FieldP256>(&mut g);
    g.finish();

    let mut g = c.benchmark_group("field2_128");
    benchmark_field::<Field2_128>(&mut g);
    g.finish();

    let mut g = c.benchmark_group("fieldp256_2");
    benchmark_field::<FieldP256_2>(&mut g);
    g.finish();
}

fn benchmark_proof_field<FE: ProofFieldElement>(g: &mut BenchmarkGroup<WallTime>) {
    g.bench_function("multiplicative_inverse", |b| {
        b.iter(|| black_box(FE::ONE).mul_inv())
    });
}

fn benchmark_all_proof_fields(c: &mut Criterion) {
    let mut g = c.benchmark_group("fieldp128");
    benchmark_proof_field::<FieldP128>(&mut g);
    g.finish();

    let mut g = c.benchmark_group("fieldp256");
    benchmark_proof_field::<FieldP256>(&mut g);
    g.finish();

    let mut g = c.benchmark_group("field2_128");
    benchmark_proof_field::<Field2_128>(&mut g);
    g.finish();
}

criterion_group!(benches, benchmark_all_fields, benchmark_all_proof_fields);
criterion_main!(benches);
