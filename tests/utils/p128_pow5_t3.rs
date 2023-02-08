use circuit_samples::circuits::poseidon_circuit::utils::Spec;

use halo2_proofs::pasta::Fp;

use super::fp3;
pub type Mds<F, const T: usize> = [[F; T]; T];

#[derive(Debug, Default, Clone)]
pub struct P128Pow5T3;

impl Spec<Fp, 3> for P128Pow5T3 {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    /// Generates `mds` corresponding to this specification.
    fn mds() -> Mds<Fp, 3> {
        fp3::MDS
    }

    /// Generates `ARKS` corresponding to this specification.
    fn arks() -> Vec<[Fp; 3]> {
        fp3::ROUND_CONSTANTS[..].to_vec()
    }

    // Generate the capacity
    fn capacity() -> u128 {
        u128::pow(2, 65)
    }

    fn pad() -> Vec<Fp> {
        vec![Fp::one()]
    }

    fn squeeze_rounds() -> usize {
        2
    }
}
