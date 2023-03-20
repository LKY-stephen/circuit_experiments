mod utils;
use crate::utils::p128_pow5_t3::P128Pow5T3;
use circuit_samples::circuits::merkle_circuit::MerklePathCircuit;
use circuit_samples::circuits::poseidon_circuit::utils::Spec;
use circuit_samples::circuits::*;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Value;
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{keygen_pk, keygen_vk};
use halo2_proofs::poly::commitment::Params;
use rand::prelude::*;
use rstest::rstest;
use utils::poseidon_hash::gen_merkle_path;

#[cfg(test)]
#[rstest]
#[case(3, 5, 35)]
#[case(2, 5, 50)]
// demo1 proves (x^3+x)y=z for case(x,y,z)
fn fuction_demo1(#[case] x: u64, #[case] y: u64, #[case] z: u64) {
    let degree = 4;
    let input = Fp::from(x);
    let c = Fp::from(y);
    let result = Fp::from(z);

    let circuit = arth_circuit::DemoCircuit1::new(input);

    let public_inputs = vec![c, result];

    let prover = MockProver::run(degree, &circuit, vec![public_inputs.clone()]).unwrap();

    if y * (x.pow(3) + x) == z {
        assert_eq!(prover.verify(), Ok(()));
    } else {
        assert!(prover.verify().is_err());
    }
}

#[cfg(test)]
#[rstest]
#[case(2)]
#[case(4)]
#[case(6)]
#[case(10)]
#[case(100)]
// proves y=poseidon(x)
fn function_poseidon(#[case] n: usize) {
    // in total inputsize + squeeze size -1 permutation
    // each permutation we have rounds only
    // add inputs has 3 lines

    let row_n = (<P128Pow5T3 as Spec<Fp, 3>>::full_rounds()
        + <P128Pow5T3 as Spec<Fp, 3>>::partial_rounds())
        * (<P128Pow5T3 as Spec<Fp, 3>>::element_size() + n)
        + 3 * n;
    let degree = (row_n as f32).log2().ceil() as u32;
    let mut rng = rand::thread_rng();
    let inputs: Vec<Fp> = (0..n)
        .map(|_| <Fp as FieldExt>::from_u128(rng.gen::<u128>()))
        .collect();
    let mut outputs = utils::poseidon_hash::hash::<Fp, P128Pow5T3, 3>(inputs.clone()).unwrap();

    let circuit = poseidon_circuit::PoseidonCircuit::<Fp, P128Pow5T3, 3>::new(inputs);

    let prover = MockProver::run(degree, &circuit, vec![outputs.clone()]).unwrap();

    prover.assert_satisfied();
    assert_eq!(prover.verify(), Ok(()));

    outputs[0] = outputs[0] + Fp::from_u128(1);
    let f_prover = MockProver::run(degree, &circuit, vec![outputs.clone()]).unwrap();

    assert!(f_prover.verify().is_err());
}

#[cfg(test)]
#[rstest]
#[case(16, 32)]
#[case(32, 32)]
fn function_merkle_32(#[case] n: usize, #[case] m: usize) {
    use circuit_samples::circuits::merkle_circuit::MerklePathCircuit;

    let row_n = (<P128Pow5T3 as Spec<Fp, 3>>::full_rounds()
        + <P128Pow5T3 as Spec<Fp, 3>>::partial_rounds())
        * (<P128Pow5T3 as Spec<Fp, 3>>::element_size() + 2)
        + 6;
    let degree = ((row_n * m) as f64).log2().ceil() as u32;

    let path = utils::poseidon_hash::gen_merkle_path::<Fp, P128Pow5T3, 3>(n, m);

    let circuit = MerklePathCircuit::<Fp, P128Pow5T3, 32, 3, 2>::new(
        path.get_left_value(),
        path.get_right_value(),
        path.get_copy_value(m),
    );
    let public = path
        .get_leaf()
        .into_iter()
        .chain(path.get_index())
        .chain(path.get_root())
        .collect::<Vec<_>>();
    let prover = MockProver::run(degree, &circuit, vec![public]).unwrap();

    prover.assert_satisfied();
    assert_eq!(prover.verify(), Ok(()));
}

#[cfg(test)]
#[rstest]
#[case(16, 32)]
#[case(32, 32)]
fn full_merkle_circuit(#[case] n: usize, #[case] m: usize) {
    use halo2_proofs::{
        plonk::{create_proof, verify_proof, SingleVerifier},
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    };
    use rand_core::OsRng;

    let leaf_size = P128Pow5T3::element_size();

    let row_n = (<P128Pow5T3 as Spec<Fp, 3>>::full_rounds()
        + <P128Pow5T3 as Spec<Fp, 3>>::partial_rounds())
        * (leaf_size + 2)
        + 6;
    let degree = ((row_n * m) as f64).log2().ceil() as u32;

    let path = gen_merkle_path::<Fp, P128Pow5T3, 3>(n, m);

    let prover_circuit = MerklePathCircuit::<Fp, P128Pow5T3, 32, 3, 2>::new(
        path.get_left_value(),
        path.get_right_value(),
        path.get_copy_value(m),
    );
    let empty: Vec<Vec<Value<Fp>>> = vec![vec![Value::unknown(); leaf_size]; m];
    let empty_copy: Vec<Value<Fp>> = vec![Value::unknown(); m + 1];
    let empty_circuit = MerklePathCircuit::<Fp, P128Pow5T3, 32, 3, 2>::new(
        empty.clone(),
        empty.clone(),
        empty_copy.clone(),
    );
    let public = path
        .get_leaf()
        .into_iter()
        .chain(path.get_index())
        .chain(path.get_root())
        .collect::<Vec<_>>();

    let params: Params<EqAffine> = Params::new(degree);
    let vk = keygen_vk(&params, &empty_circuit).expect("failed to generate vk");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("failed to generate pk");
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
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let strategy = SingleVerifier::new(&params);
    assert!(verify_proof(
        &params,
        pk.get_vk(),
        strategy,
        &[&[&public]],
        &mut transcript,
    )
    .is_ok());
}
