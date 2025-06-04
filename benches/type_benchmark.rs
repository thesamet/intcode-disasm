use criterion::{criterion_group, criterion_main, Criterion, SamplingMode};
use disasm::disasm::{
    v3::{
        analysis::{self, binary_to_folded_ssa},
        type_inference,
    },
    SymbolRenaming,
};
use std::hint::black_box;

fn criterion_benchmark(c: &mut Criterion) {
    let input = std::fs::read_to_string("../aoc-2019-rust/data/inputs/25.txt").unwrap();
    let binary = input
        .trim()
        .split(',')
        .map(|x| x.parse().unwrap())
        .collect::<Vec<i128>>();
    let model = binary_to_folded_ssa(binary).unwrap();
    let mut group = c.benchmark_group("flat-types");
    group.sample_size(20);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function("types", |b| {
        b.iter(|| {
            let _ = type_inference::Solver::run(black_box(model.clone()), &SymbolRenaming::new());
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
