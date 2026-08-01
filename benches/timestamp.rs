use criterion::{black_box, criterion_group, criterion_main, Criterion};
use forensic_rs::prelude::*;

fn timestamp_operations(criterion: &mut Criterion) {
    let timestamp = ForensicTimestamp::try_with_ymd_and_hms_nanos(
        2024,
        2,
        3,
        14,
        10,
        23,
        595_970_600,
        Some(0),
    )
    .unwrap();

    let mut group = criterion.benchmark_group("timestamp");
    group.bench_function("from_win_filetime", |bencher| {
        bencher.iter(|| black_box(ForensicTimestamp::from_win_filetime(133_514_430_235_959_706)))
    });
    group.bench_function("calendar_components", |bencher| {
        bencher.iter(|| black_box((timestamp.year(), timestamp.month(), timestamp.day())))
    });
    group.bench_function("little_endian_round_trip", |bencher| {
        bencher.iter(|| {
            black_box(ForensicTimestamp::from_le_bytes(timestamp.to_le_bytes()).unwrap())
        })
    });
    group.bench_function("instant_comparison", |bencher| {
        bencher.iter(|| black_box(timestamp.cmp_instant(timestamp)))
    });
    group.finish();
}

criterion_group!(benches, timestamp_operations);
criterion_main!(benches);
