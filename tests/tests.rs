use circuit_samples::circuits::*;
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::Fp;
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

    let circuit = arth_circuits::DemoCircuit1::new(input);

    let public_inputs = vec![c, result];

    let prover = MockProver::run(degree, &circuit, vec![public_inputs.clone()]).unwrap();

    if y * (x.pow(3) + x) == z {
        assert_eq!(prover.verify(), Ok(()));
    } else {
        assert!(prover.verify().is_err());
    }
}
