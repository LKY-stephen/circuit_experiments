mod utils;
use crate::utils::p128_pow5_t3::P128Pow5T3;
use circuit_samples::circuits::poseidon_circuit::utils::Spec;
use circuit_samples::circuits::*;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::Fp;
use rand::prelude::*;
use rstest::rstest;

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
#[case(16)]
#[case(32)]
fn function_merkle_32(#[case] n: usize) {
    let m = 32_usize;
    use circuit_samples::circuits::merkle_circuit::MerklePathCircuit;

    let row_n = (<P128Pow5T3 as Spec<Fp, 3>>::full_rounds()
        + <P128Pow5T3 as Spec<Fp, 3>>::partial_rounds())
        * (<P128Pow5T3 as Spec<Fp, 3>>::element_size() + 2)
        + 6;
    let degree = ((row_n * m) as f64).log2().ceil() as u32;
    let mut rng = rand::thread_rng();
    let inputs: Vec<Fp> = (0..2 * n + 2)
        .map(|_| <Fp as FieldExt>::from_u128(rng.gen::<u128>()))
        .collect();

    let mut left = vec![vec![inputs[0].to_owned(), inputs[1].to_owned()]];
    let mut right = vec![vec![inputs[2].to_owned(), inputs[3].to_owned()]];

    let mut index = vec![];
    let init_index = rng.gen_bool(0.5);
    let leaf_input = match init_index {
        true => {
            index.push(Fp::one());
            vec![inputs[2].to_owned(), inputs[3].to_owned()]
        }
        false => {
            index.push(Fp::zero());
            vec![inputs[0].to_owned(), inputs[1].to_owned()]
        }
    };

    // put element size
    for i in 1..=m {
        let bit = rng.gen_bool(0.5);
        // add path
        if i < m {
            index.push(match bit {
                true => Fp::one(),
                false => Fp::zero(),
            });
        }

        if i <= n {
            let hash_inputs = left[i - 1]
                .to_owned()
                .into_iter()
                .chain(right[i - 1].to_owned())
                .collect::<Vec<_>>();
            let hash =
                utils::poseidon_hash::hash::<Fp, P128Pow5T3, 3>(hash_inputs.clone()).unwrap();
            let element = match i < n {
                true => vec![inputs[2 * i + 2].to_owned(), inputs[2 * i + 3].to_owned()],

                // last line is duplicated
                false => hash.clone(),
            };

            match bit {
                true => {
                    right.push(hash);
                    left.push(element);
                }
                false => {
                    left.push(hash);
                    right.push(element);
                }
            };
        }
    }

    let root = left
        .get(n as usize)
        .expect("get root value failed")
        .to_owned();

    let circuit = MerklePathCircuit::<Fp, P128Pow5T3, 32, 3, 2>::new(left, right, init_index);
    let public = leaf_input
        .into_iter()
        .chain(index)
        .chain(root)
        .collect::<Vec<_>>();
    let prover = MockProver::run(degree, &circuit, vec![public]).unwrap();

    prover.assert_satisfied();
    assert_eq!(prover.verify(), Ok(()));
}
