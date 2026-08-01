use criterion::{black_box, criterion_group, criterion_main, Criterion};
use forensic_rs::utils::unpack::{read_u32_le_at, read_u64_le_at};

fn unpack_at_offsets(criterion: &mut Criterion) {
    let buffer: Vec<u8> = (0..16_384).map(|index| (index % 251) as u8).collect();
    let offsets: Vec<usize> = (0..1_024).map(|index| (index * 13) % 16_376).collect();

    let mut group = criterion.benchmark_group("unpack");
    group.bench_function("read_u32_le_at", |bencher| {
        bencher.iter(|| {
            let mut total = 0u32;
            for &offset in &offsets {
                total = total.wrapping_add(read_u32_le_at(&buffer, offset).unwrap());
            }
            black_box(total)
        });
    });
    group.bench_function("read_u64_le_at", |bencher| {
        bencher.iter(|| {
            let mut total = 0u64;
            for &offset in &offsets {
                total = total.wrapping_add(read_u64_le_at(&buffer, offset).unwrap());
            }
            black_box(total)
        });
    });
    group.finish();
}

criterion_group!(benches, unpack_at_offsets);
criterion_main!(benches);