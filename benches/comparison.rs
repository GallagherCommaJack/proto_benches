use criterion::*;
use proto_benches::*;
use std::collections::HashMap;

const NUM_CENS: usize = 10_000;
const NUM_PKS: usize = 100_000;

fn prepare_cens() -> (Vec<PK>, HashMap<CEN, i64, HashHasherBuilder>) {
    let mut pks = Vec::with_capacity(NUM_PKS);
    let mut cens = HashMap::with_capacity_and_hasher(NUM_CENS, Default::default());
    let mut reader = blake3::Hasher::new().finalize_xof();

    let mut pk_buf = [0u8; 32];
    for _ in 0..NUM_PKS {
        reader.fill(&mut pk_buf);
        pks.push(pk_buf);
    }

    let mut cen_buf = [0u8; CEN_BYTES];
    for i in 0..NUM_CENS as i64 {
        reader.fill(&mut cen_buf);
        cens.insert(cen_buf, i);
    }

    (pks, cens)
}

fn bench_jack_approach(c: &mut Criterion) {
    let (pks, cens) = prepare_cens();
    let mut group = c.benchmark_group("Jack approaches");
    group.throughput(Throughput::Bytes(32));

    group.bench_function("jack approach baseline", |b| {
        let mut i = 0;
        b.iter(|| {
            check_cen_membership(black_box(&cens), pks[i % pks.len()], calculate_cens_hashing);
            i += 1
        });
    });

    group.bench_function("jack approach batched", |b| {
        let mut i = 0;
        b.iter(|| {
            check_cen_membership(
                black_box(&cens),
                pks[i % pks.len()],
                calculate_cens_hashing_batch,
            );
            i += 1
        });
    });

    group.bench_function("jack approach chacha", |b| {
        let mut i = 0;
        b.iter(|| {
            check_cen_membership(black_box(&cens), pks[i % pks.len()], calculate_cens_chacha8);
            i += 1
        });
    });
}

fn bench_manu_approach(c: &mut Criterion) {
    let (pks, cens) = prepare_cens();
    let cens: Vec<_> = cens.into_iter().collect();

    let mut group = c.benchmark_group("Manu approaches");
    group.throughput(Throughput::Bytes(32));

    group.bench_function("manu approach soft", |b| {
        let mut i = 0;
        b.iter(|| {
            check_cen_manu(black_box(&cens), pks[i % pks.len()]);
            i += 1
        });
    });

    #[cfg(feature = "aesni")]
    group.bench_function("manu approach ni", |b| {
        let mut i = 0;
        b.iter(|| {
            check_cen_manu_ni(black_box(&cens), pks[i % pks.len()]);
            i += 1
        });
    });
}

criterion_group!(approaches, bench_jack_approach, bench_manu_approach);
criterion_main!(approaches);
