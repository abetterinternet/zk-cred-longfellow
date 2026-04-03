use criterion::{BenchmarkGroup, BenchmarkId, Criterion, criterion_group, measurement::WallTime};
use std::hint::black_box;
use zk_cred_longfellow::fields::{
    ProofFieldElement, field2_128::Field2_128, fieldp128::FieldP128, fieldp256::FieldP256,
};

fn benchmark_extend<FE: ProofFieldElement>(g: &mut BenchmarkGroup<WallTime>) {
    struct Parameters {
        input_size: usize,
        output_size: usize,
    }

    for Parameters {
        input_size,
        output_size,
    } in [
        Parameters {
            input_size: 8,
            output_size: 16,
        },
        Parameters {
            input_size: 100,
            output_size: 200,
        },
        Parameters {
            input_size: 981,
            output_size: 2945,
        },
        Parameters {
            input_size: 1363,
            output_size: 4096,
        },
    ] {
        let input = vec![FE::ZERO; input_size];
        let context = FE::extend_precompute(input_size, output_size);
        g.bench_function(
            BenchmarkId::from_parameter(format_args!("{input_size}_to_{output_size}")),
            |b| {
                b.iter(|| FE::extend(black_box(&input), black_box(&context)));
            },
        );
    }
}

fn benchmark_all(c: &mut Criterion) {
    let mut g = c.benchmark_group("extend_fieldp128");
    benchmark_extend::<FieldP128>(&mut g);
    g.finish();

    let mut g = c.benchmark_group("extend_fieldp256");
    benchmark_extend::<FieldP256>(&mut g);
    g.finish();

    let mut g = c.benchmark_group("extend_field2_128");
    benchmark_extend::<Field2_128>(&mut g);
    g.finish();
}

criterion_group!(benches, benchmark_all);

fn main() {
    let git_version = git_version::git_version!(fallback = "unknown");
    println!("Git revision: {git_version}");
    println!();

    benches();
    Criterion::default().configure_from_args().final_summary();
}
