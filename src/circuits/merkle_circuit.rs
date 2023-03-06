use std::marker::PhantomData;

use crate::chips::merkle_chip::{MerklePathChip, MerklePathConfig, MerklePathInstruction};

use super::super::chips::poseidon_chip::*;
use super::poseidon_circuit::utils::Spec;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};

#[derive(Clone)]
pub struct MerkleConfig<F: FieldExt, S: Spec<F, W>, const M: usize, const W: usize, const I: usize>
{
    merkle_config: MerklePathConfig<I>,
    poseidon_config: PoseidonArthConfig<F, W>,
    _marker: PhantomData<S>,
}

// implementation for 5-posiedon
// For each input, we fixed the padding as [x,1,0,0,...,0]
// inputs permutation rounds will go for all abosrb
#[derive(Clone, Default)]
pub struct MerklePathCircuit<
    F: FieldExt,
    S: Spec<F, W>,
    const M: usize,
    const W: usize,
    const I: usize,
> {
    left: Vec<[Value<F>; I]>,
    right: Vec<[Value<F>; I]>,
    _marker: PhantomData<S>,
}

impl<
        F: FieldExt,
        S: Spec<F, W> + Clone + Default,
        const M: usize,
        const W: usize,
        const I: usize,
    > Circuit<F> for MerklePathCircuit<F, S, M, W, I>
{
    type Config = MerkleConfig<F, S, M, W, I>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let left = (0..I)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let right = (0..I)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let hash = (0..I)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let copy_flag = meta.advice_column();
        let index_flag = meta.advice_column();

        let states: Vec<_> = (0..W).map(|_| meta.advice_column()).collect();
        let arks: Vec<_> = (0..W).map(|_| meta.fixed_column()).collect();

        // public column for output
        let output = meta.instance_column();

        // We also need an instance column to store public inputs.
        let mds = S::mds();
        let ark_paras = S::arks();

        MerkleConfig {
            merkle_config: MerklePathChip::configure(
                meta, left, right, hash, copy_flag, index_flag, output,
            ),
            poseidon_config: PoseidonChip::configure(
                meta,
                states.try_into().unwrap(),
                output,
                arks.try_into().unwrap(),
                mds,
                ark_paras,
                S::capacity(),
            ),
            _marker: PhantomData,
        }
    }

    fn synthesize(
        &self,
        config: MerkleConfig<F, S, M, W, I>,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let size = S::element_size();

        // element size is correct
        assert_eq!(size, I);

        // path length is correct
        let n = self.left.len() - 1;
        assert!(n <= M);

        let poseidon_chip = PoseidonChip::new(config.poseidon_config);
        let fr = S::full_rounds();
        let pr = S::partial_rounds();

        let merkle_chip = MerklePathChip::new(config.merkle_config);

        // chunks and pad
        let padded_left = self
            .left
            .clone()
            .into_iter()
            .map(|c| {
                c.to_vec()
                    .into_iter()
                    .chain(S::pad().into_iter().map(Value::known))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let padded_right = self
            .right
            .clone()
            .into_iter()
            .map(|c| {
                c.to_vec()
                    .into_iter()
                    .chain(S::pad().into_iter().map(Value::known))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // compute hash
        let mut left_nodes: Vec<[AssignedCell<F, F>; I]> = vec![];
        let mut right_nodes: Vec<[AssignedCell<F, F>; I]> = vec![];
        let mut hash_nodes: Vec<[AssignedCell<F, F>; I]> = vec![];

        for i in 0..n {
            let s = poseidon_chip
                .initiate(&mut layouter)
                .expect("failed to init hasher");
            let (s, l) = poseidon_chip
                .load_inputs(&mut layouter, s.clone(), &padded_left[i])
                .expect("failed to load left input");
            let s = poseidon_chip
                .permutation(&mut layouter, s, fr, pr)
                .expect("failed to permutate left input");
            let (s, r) = poseidon_chip
                .load_inputs(&mut layouter, s.clone(), &padded_right[i])
                .expect("failed to load right input");

            let h = poseidon_chip
                .permutation(&mut layouter, s, fr, pr)
                .expect("failed to permutate right input");
            left_nodes.push(
                l.into_iter()
                    .map(|d| d.0)
                    .take(I)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("left node is not correct"),
            );
            right_nodes.push(
                r.into_iter()
                    .map(|d| d.0)
                    .take(I)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("right node is not correct"),
            );
            hash_nodes.push(
                h.0.into_iter()
                    .map(|d| d.0)
                    .take(I)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("hash node is not correct"),
            );
        }

        // now process root

        for _ in n..M + 1 {
            let s = poseidon_chip
                .initiate(&mut layouter)
                .expect("failed to init hasher");
            let (s, l) = poseidon_chip
                .load_inputs(&mut layouter, s.clone(), &padded_left[n])
                .expect("failed to load left root");
            let s = poseidon_chip
                .permutation(&mut layouter, s, fr, pr)
                .expect("failed to permutate left root");
            let (s, r) = poseidon_chip
                .load_inputs(&mut layouter, s.clone(), &padded_right[n])
                .expect("failed to load right root");

            let h = poseidon_chip
                .permutation(&mut layouter, s, fr, pr)
                .expect("failed to permutate right root");
            left_nodes.push(
                l.into_iter()
                    .map(|d| d.0)
                    .take(I)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("left root is not correct"),
            );
            right_nodes.push(
                r.into_iter()
                    .map(|d| d.0)
                    .take(I)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("right root is not correct"),
            );
            hash_nodes.push(
                h.0.into_iter()
                    .map(|d| d.0)
                    .take(I)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("hash node is not correct"),
            );
        }

        let selection = merkle_chip.load_leaves(
            &mut layouter,
            left_nodes[0].clone(),
            right_nodes[0].clone(),
        )?;

        merkle_chip.expose_public(&mut layouter, selection, 0)?;
        let root_node =
            merkle_chip.load_path(&mut layouter, left_nodes, right_nodes, hash_nodes, M, n)?;

        merkle_chip.expose_public(&mut layouter, root_node, M + I)?;
        return Ok(());
    }
}

impl<
        F: FieldExt,
        S: Spec<F, W> + Clone + Default,
        const M: usize,
        const W: usize,
        const I: usize,
    > MerklePathCircuit<F, S, M, W, I>
{
    /// input the real path
    /// [left leave, right leave]
    /// [left node, right node]
    /// ...
    /// [root, root]
    pub fn new(left: Vec<Vec<F>>, right: Vec<Vec<F>>) -> MerklePathCircuit<F, S, M, W, I> {
        assert_eq!(left.len(), right.len());
        MerklePathCircuit {
            left: left
                .into_iter()
                .map(|v| {
                    v.into_iter()
                        .map(Value::known)
                        .collect::<Vec<_>>()
                        .try_into()
                        .expect("left inputs error")
                })
                .collect(),
            right: right
                .into_iter()
                .map(|v| {
                    v.into_iter()
                        .map(Value::known)
                        .collect::<Vec<_>>()
                        .try_into()
                        .expect("right inputs error")
                })
                .collect(),
            _marker: PhantomData,
        }
    }
}
