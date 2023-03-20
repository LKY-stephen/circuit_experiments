use std::time::Duration;

use circuit_samples::circuits::{merkle_circuit::MerklePathCircuit, poseidon_circuit::utils::Spec};
use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::{
    circuit::Value,
    pasta::{EqAffine, Fp},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};

#[path = "../tests/utils/mod.rs"]
mod utils;
use rand_core::OsRng;
use utils::{p128_pow5_t2::P128Pow5T2, p128_pow5_t3::P128Pow5T3, poseidon_hash::gen_merkle_path};

fn proof_criterion_256(c: &mut Criterion) {
    generate_proof_fn::<P128Pow5T3, 32, 3, 2>(c);

    generate_proof_fn::<P128Pow5T3, 48, 3, 2>(c);

    generate_proof_fn::<P128Pow5T3, 64, 3, 2>(c);
}

fn proof_criterion_128(c: &mut Criterion) {
    generate_proof_fn::<P128Pow5T2, 32, 3, 1>(c);

    generate_proof_fn::<P128Pow5T2, 48, 3, 1>(c);

    generate_proof_fn::<P128Pow5T2, 64, 3, 1>(c);
}

fn generate_proof_fn<S: Spec<Fp, W>, const M: usize, const W: usize, const I: usize>(
    c: &mut Criterion,
) {
    for n in [1, M / 4, M / 2, M] {
        let (params, pk, public, prover_circuit) = prepare_circuits::<S, M, W, I>(n);
        c.bench_function(&format!("generate proof for n:{n} m: {M} I: {I}"), |b| {
            b.iter(|| {
                // Create a proof
                create_proof(
                    &params,
                    &pk,
                    &[prover_circuit.clone()],
                    &[&[&public]],
                    OsRng,
                    &mut Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]),
                )
                .expect("proof generation should not fail");
            })
        });

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        // Create a proof
        create_proof(
            &params,
            &pk,
            &[prover_circuit],
            &[&[&public]],
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof: Vec<u8> = transcript.finalize();
        let size = proof.len();
        println!("proof size for n:{n} m: {M} I: {I} is {size} Bytes");

        c.bench_function(&format!("verify proof for n:{n} m: {M} I: {I}"), |b| {
            b.iter(|| {
                assert!(verify_proof(
                    &params,
                    pk.get_vk(),
                    SingleVerifier::new(&params),
                    &[&[&public]],
                    &mut Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]),
                )
                .is_ok());
            })
        });
    }
}

fn prepare_circuits<S: Spec<Fp, W>, const M: usize, const W: usize, const I: usize>(
    n: usize,
) -> (
    Params<EqAffine>,
    ProvingKey<EqAffine>,
    Vec<Fp>,
    MerklePathCircuit<Fp, S, M, W, I>,
) {
    assert_eq!(S::element_size(), I);

    let row_n = (S::full_rounds() + S::partial_rounds()) * (I + 2) + 6;
    let degree = ((row_n * M) as f64).log2().ceil() as u32;

    let path = gen_merkle_path::<Fp, S, W>(n, M);

    let prover_circuit = MerklePathCircuit::<Fp, S, M, W, I>::new(
        path.get_left_value(),
        path.get_right_value(),
        path.get_copy_value(M),
    );
    let empty: Vec<Vec<Value<Fp>>> = vec![vec![Value::unknown(); I]; M];
    let empty_copy: Vec<Value<Fp>> = vec![Value::unknown(); M + 1];
    let empty_circuit =
        MerklePathCircuit::<Fp, S, M, W, I>::new(empty.clone(), empty.clone(), empty_copy.clone());
    let public = path
        .get_leaf()
        .into_iter()
        .chain(path.get_index())
        .chain(path.get_root())
        .collect::<Vec<_>>();

    let params: Params<EqAffine> = Params::new(degree);
    let vk = keygen_vk(&params, &empty_circuit).expect("failed to generate vk");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("failed to generate pk");

    return (params, pk, public, prover_circuit);
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(30)).sample_size(10);
    targets = proof_criterion_128,proof_criterion_256
}
criterion_main!(benches);
