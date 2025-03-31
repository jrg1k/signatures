use criterion::measurement::Measurement;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use criterion_cycles_per_byte::CyclesPerByte;
use hybrid_array::{Array, ArraySize};
use ml_dsa::{B32, KeyGen, MlDsa65, Signature, SigningKey, VerifyingKey};
use rand::CryptoRng;

pub fn rand<L: ArraySize, R: CryptoRng + ?Sized>(rng: &mut R) -> Array<u8, L> {
    let mut val = Array::<u8, L>::default();
    rng.fill_bytes(&mut val);
    val
}

fn criterion_benchmark<M: Measurement>(c: &mut Criterion<M>) {
    let mut rng = rand::rng();

    let mut ml_dsa = c.benchmark_group("ML-DSA");

    // Key generation
    ml_dsa.bench_function("keygen", |b| {
        b.iter_batched(
            || {
                let xi: B32 = rand(&mut rng);
                xi
            },
            |xi| {
                let kp = MlDsa65::key_gen_internal(&xi);
                let _sk_bytes = kp.signing_key().encode();
                let _vk_bytes = kp.verifying_key().encode();
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Signing
    ml_dsa.bench_function("sign", |b| {
        b.iter_batched(
            || {
                let xi: B32 = rand(&mut rng);
                let m: B32 = rand(&mut rng);
                let ctx: B32 = rand(&mut rng);

                let kp = MlDsa65::key_gen_internal(&xi);
                let sk = kp.signing_key();

                let sk_bytes = sk.encode();
                (sk_bytes, m, ctx)
            },
            |(sk_bytes, m, ctx)| {
                let sk = SigningKey::<MlDsa65>::decode(&sk_bytes);
                sk.sign_deterministic(&m, &ctx)
            },
            BatchSize::SmallInput,
        );
    });

    // Verifying
    ml_dsa.bench_function("verify", |b| {
        b.iter_batched(
            || {
                let xi: B32 = rand(&mut rng);
                let m: B32 = rand(&mut rng);
                let ctx: B32 = rand(&mut rng);

                let kp = MlDsa65::key_gen_internal(&xi);
                let sk = kp.signing_key();
                let vk = kp.verifying_key();
                let sig = sk.sign_deterministic(&m, &ctx).unwrap();

                let vk_bytes = vk.encode();
                let sig_bytes = sig.encode();
                (vk_bytes, sig_bytes, m, ctx)
            },
            |(vk_bytes, sig_bytes, m, ctx)| {
                let vk = VerifyingKey::<MlDsa65>::decode(&vk_bytes);
                let sig = Signature::<MlDsa65>::decode(&sig_bytes).unwrap();
                vk.verify_with_context(&m, &ctx, &sig)
            },
            BatchSize::SmallInput,
        );
    });

    // Round trip
    ml_dsa.bench_function("round_trip", |b| {
        b.iter_batched(
            || {
                let xi: B32 = rand(&mut rng);
                let m: B32 = rand(&mut rng);
                let ctx: B32 = rand(&mut rng);

                (xi, m, ctx)
            },
            |(xi, m, ctx)| {
                let kp = MlDsa65::key_gen_internal(&xi);
                let sig = kp.signing_key().sign_deterministic(&m, &ctx).unwrap();
                kp.verifying_key().verify_with_context(&m, &ctx, &sig)
            },
            BatchSize::SmallInput,
        );
    });

    ml_dsa.finish();
}

criterion::criterion_group!(
    name = benches;
    config = criterion::Criterion::default().with_measurement(CyclesPerByte);
    targets = criterion_benchmark
);
criterion_main!(benches);
