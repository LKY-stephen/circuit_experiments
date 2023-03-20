use halo2_proofs::arithmetic::FieldExt;
use std::fmt;

/// The type used to hold the MDS matrix and its inverse.
pub type Mds<F, const WIDTH: usize> = [[F; WIDTH]; WIDTH];

/// A specification for a Poseidon permutation.
/// The input should be a field F
/// the sponge width is WIDTH
/// Number of full round and partial rounds are fixed
pub trait Spec<F: FieldExt, const WIDTH: usize>: fmt::Debug + Clone + Default {
    /// The number of full rounds for this specification.
    ///
    /// This must be an even number.
    fn full_rounds() -> usize;

    /// The number of partial rounds for this specification.
    fn partial_rounds() -> usize;

    /// Generates `mds` corresponding to this specification.
    fn mds() -> Mds<F, WIDTH>;

    /// Generates `ARKS` corresponding to this specification.
    fn arks() -> Vec<[F; WIDTH]>;

    // Generate the capacity
    fn capacity() -> u128;

    // Return the Pad Element;
    fn pad() -> Vec<F>;

    // element size
    fn element_size() -> usize;
}
