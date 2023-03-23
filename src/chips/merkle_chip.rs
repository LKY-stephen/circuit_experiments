// Since we need to verify the hash computation
// The constraints will be an extension to the poseidon_chip's
// with additional merkle related constraints.

use std::{marker::PhantomData, vec};

use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Constraints, Error,
        Expression::{self},
        Instance, Selector,
    },
    poly::Rotation,
};

#[derive(Debug, Clone)]
pub struct Node<F: PrimeField, const I: usize>([AssignedCell<F, F>; I]);

pub trait MerklePathInstruction<F: PrimeField, const I: usize>: Chip<F> {
    /// Variable representing a tree node
    type Node;

    /// Loads a left child, a right child and paths
    /// return the final root
    fn load_path(
        &self,
        layouter: &mut impl Layouter<F>,
        left: Vec<[AssignedCell<F, F>; I]>,
        right: Vec<[AssignedCell<F, F>; I]>,
        hash: Vec<[AssignedCell<F, F>; I]>,
        copy: &Vec<Value<F>>,
        m: usize,
        n: usize,
    ) -> Result<Self::Node, Error>;

    /// Loads a left child, a right child
    /// return a node of its selection according to
    /// index
    fn load_leaves(
        &self,
        layouter: &mut impl Layouter<F>,
        left: [AssignedCell<F, F>; I],
        right: [AssignedCell<F, F>; I],
    ) -> Result<(), Error>;

    /// check the final result with index
    fn expose_public(
        &self,
        layouter: &mut impl Layouter<F>,
        num: Self::Node,
        row: usize,
    ) -> Result<(), Error>;
}

pub struct MerklePathChip<F: PrimeField, const I: usize> {
    config: MerklePathConfig<I>,
    _marker: PhantomData<F>,
}

///
/// The chip handles three
#[derive(Clone, Debug)]
pub struct MerklePathConfig<const I: usize> {
    /// private input for element
    value: [Column<Advice>; I],

    /// flag for hash and copy
    copy_flag: Column<Advice>,

    /// flag for left child or right child
    index_flag: Column<Advice>,

    /// This is the public input (instance) column.
    public: Column<Instance>,

    /// selector for hash query
    s_hash: Selector,

    /// selector for hash query
    s_pub: Selector,
}

impl<F: PrimeField, const I: usize> MerklePathChip<F, I> {
    pub fn new(config: MerklePathConfig<I>) -> Self {
        MerklePathChip {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        value: [Column<Advice>; I],
        copy_flag: Column<Advice>,
        index_flag: Column<Advice>,
        public: Column<Instance>,
    ) -> <Self as Chip<F>>::Config {
        // equality checks for output and internal states
        for i in 0..I {
            meta.enable_equality(value[i]);
        }

        meta.enable_equality(index_flag);

        let s_hash = meta.selector();
        let s_pub = meta.selector();

        let one = Expression::Constant(F::ONE);
        let bool_constraint = |v: Expression<F>| v.clone() * (one.clone() - v);

        let copy_flag_constraint =
            |before: Expression<F>, after: Expression<F>| before * (one.clone() - after);

        // constraints the hash and copy constraints
        meta.create_gate("Copy_Hash", |meta| {
            let s_hash = meta.query_selector(s_hash);

            // we store values as
            // value         copy      index      s_hash
            // left           -          -          0
            // right          -          -          0
            // hash          0/1        0/1         1
            // next left      -          -          0
            // next right     -          -          0

            let p_left_v = (0..I)
                .map(|i| meta.query_advice(value[i], Rotation(-2)))
                .collect::<Vec<_>>();

            let p_right_v = (0..I)
                .map(|i| meta.query_advice(value[i], Rotation::prev()))
                .collect::<Vec<_>>();

            let p_hash_v = (0..I)
                .map(|i| meta.query_advice(value[i], Rotation::cur()))
                .collect::<Vec<_>>();

            let n_copy = meta.query_advice(copy_flag, Rotation(3));
            let copy = meta.query_advice(copy_flag, Rotation::cur());
            let index = meta.query_advice(index_flag, Rotation::cur());

            let left_v = (0..I)
                .map(|i| meta.query_advice(value[i], Rotation::next()))
                .collect::<Vec<_>>();

            let right_v = (0..I)
                .map(|i| meta.query_advice(value[i], Rotation(2)))
                .collect::<Vec<_>>();

            // copy is zero until some point it becomes one (p_copy*(1-copy)).
            // index is bool value
            // (1-copy)*(p_hash - (1-index)*left -index * right) is the hash constraint
            // copy*((1-index)*(p_left-left) + (index) (p_right - right)) is the copy constraint

            let hash_constraint = (0..I)
                .map(|i| {
                    (one.clone() - copy.clone())
                        * (p_hash_v[i].clone()
                            - (one.clone() - index.clone()) * left_v[i].clone()
                            - index.clone() * right_v[i].clone())
                })
                .collect::<Vec<_>>();
            let copy_constraint = (0..I)
                .map(|i| {
                    copy.clone()
                        * ((one.clone() - index.clone())
                            * (p_left_v[i].clone() - left_v[i].clone())
                            + index.clone() * (p_right_v[i].clone() - right_v[i].clone()))
                })
                .collect::<Vec<_>>();

            let constraints = vec![
                bool_constraint(n_copy.clone()),
                bool_constraint(copy.clone()),
                copy_flag_constraint(copy.clone(), n_copy.clone()),
                bool_constraint(index),
            ]
            .into_iter()
            .chain(hash_constraint)
            .chain(copy_constraint);
            Constraints::with_selector(s_hash, constraints)
        });

        // constraints the hash and copy for the first layer inputs
        meta.create_gate("PUB_SELECT", |meta| {
            let s_pub = meta.query_selector(s_pub);

            // we store values as
            // value         copy      index      s_pub
            // left           -          -          0
            // right          -          -          0
            // hash          0/1        0/1         1

            let left_v = (0..I)
                .map(|i| meta.query_advice(value[i], Rotation(-2)))
                .collect::<Vec<_>>();

            let right_v = (0..I)
                .map(|i| meta.query_advice(value[i], Rotation::prev()))
                .collect::<Vec<_>>();

            let hash_v = (0..I)
                .map(|i| meta.query_advice(value[i], Rotation::cur()))
                .collect::<Vec<_>>();

            let index = meta.query_advice(index_flag, Rotation::cur());
            let copy = meta.query_advice(copy_flag, Rotation::cur());

            // copy left to hash if index is 0 other wise copy the right one

            let copy_constraint = (0..I)
                .map(|i| {
                    (one.clone() - index.clone()) * (left_v[i].clone() - hash_v[i].clone())
                        + index.clone() * (right_v[i].clone() - hash_v[i].clone())
                })
                .collect::<Vec<_>>();

            let constraints = vec![bool_constraint(index.clone()), copy.clone()]
                .into_iter()
                .chain(copy_constraint);
            Constraints::with_selector(s_pub, constraints)
        });

        MerklePathConfig {
            value,
            public,
            copy_flag,
            index_flag,
            s_hash,
            s_pub,
        }
    }
}

impl<F: PrimeField, const I: usize> MerklePathInstruction<F, I> for MerklePathChip<F, I> {
    type Node = Node<F, I>;

    fn load_path(
        &self,
        layouter: &mut impl Layouter<F>,
        left: Vec<[AssignedCell<F, F>; I]>,
        right: Vec<[AssignedCell<F, F>; I]>,
        hash: Vec<[AssignedCell<F, F>; I]>,
        copy: &Vec<Value<F>>,
        m: usize,
        n: usize,
    ) -> Result<Self::Node, Error> {
        let config = self.config();
        assert_eq!(m + 1, right.len());
        assert_eq!(m + 1, left.len());
        assert_eq!(m + 1, copy.len());
        assert_eq!(m, hash.len());
        assert!(n <= m);

        layouter.assign_region(
            || "load path",
            |mut region: Region<'_, F>| {
                // from first n row we do the following
                //
                // |  value  | copy | index| s_hash|
                // |  left1  |  *   |  *   |    0  |
                // |  right1 |  *   |  *   |    0  |
                // |  hash1  |  0   |  0   |    1  |
                // ....
                // hash(i) =  left(i+1) if index =0 else right(i+1)

                for i in 0..n {
                    let cur_pos = i * 3;
                    let hash_pos = cur_pos + 2;
                    for j in 0..I {
                        left[i][j].copy_advice(
                            || "assign left",
                            &mut region,
                            config.value[j],
                            cur_pos,
                        )?;
                        right[i][j].copy_advice(
                            || "assign right",
                            &mut region,
                            config.value[j],
                            cur_pos + 1,
                        )?;
                        hash[i][j].copy_advice(
                            || "copy hash",
                            &mut region,
                            config.value[j],
                            hash_pos,
                        )?;
                    }

                    config.s_hash.enable(&mut region, hash_pos)?;

                    region.assign_advice(
                        || "assign copy",
                        config.copy_flag,
                        hash_pos,
                        || copy[i],
                    )?;
                }

                // after the pathes are handled, we need to process root
                //
                // |  value  | copy | index| s_hash|
                // |  root   |  *   |  *   |    0  |
                // |  root   |  *   |  *   |    0  |
                // |  hash   |  1   |  0   |    1  |
                // ....
                for i in n..m {
                    let cur_pos = i * 3;
                    let hash_pos = cur_pos + 2;
                    for j in 0..I {
                        left[i][j].copy_advice(
                            || "assign left",
                            &mut region,
                            config.value[j],
                            cur_pos,
                        )?;
                        right[i][j].copy_advice(
                            || "assign right",
                            &mut region,
                            config.value[j],
                            cur_pos + 1,
                        )?;
                        hash[i][j].copy_advice(
                            || "copy hash",
                            &mut region,
                            config.value[j],
                            hash_pos,
                        )?;
                    }

                    config.s_hash.enable(&mut region, hash_pos)?;

                    region.assign_advice(
                        || "assign copy",
                        config.copy_flag,
                        hash_pos,
                        || copy[i],
                    )?;
                }

                // we assign index independently since it has different position
                for i in 1..m {
                    // we skip the first index since it is for leaf
                    region.assign_advice_from_instance(
                        || "assign index",
                        config.public,
                        I + i,
                        config.index_flag,
                        i * 3 - 1,
                    )?;
                }
                // finally we put two roots at the last two row
                //
                // |  value  | copy | index| s_hash|
                // |  hash   |  0   |  0/1 |    1  |
                // |  root   |  *   |   *  |    0  |
                // |  root   |  *   |   *  |    0  |
                // ....

                let cur_pos = m * 3;
                let root = (0..I)
                    .map(|j| {
                        let left_v = left[m][j]
                            .copy_advice(
                                || "assign left root",
                                &mut region,
                                config.value[j],
                                cur_pos,
                            )
                            .expect("failed to get left root value");
                        // right is just a copy
                        left[m][j]
                            .copy_advice(
                                || "assign right root",
                                &mut region,
                                config.value[j],
                                cur_pos + 1,
                            )
                            .expect("failed to get right root value");

                        return left_v;
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("Failed to compute root");

                // one last index is meaningless but will be queried
                region.assign_advice(
                    || "assign last index to one",
                    config.index_flag,
                    cur_pos - 1,
                    || Value::known(F::ZERO),
                )?;

                region.assign_advice(
                    || "assign last index to one",
                    config.copy_flag,
                    cur_pos + 2,
                    || Value::known(F::ONE),
                )?;
                return Ok(Node(root));
            },
        )
    }

    fn expose_public(
        &self,
        layouter: &mut impl Layouter<F>,
        num: Self::Node,
        row: usize,
    ) -> Result<(), Error> {
        let config = self.config();

        for i in 0..I {
            layouter.constrain_instance(num.0[i].cell(), config.public, row + i)?;
        }
        Ok(())
    }

    fn load_leaves(
        &self,
        layouter: &mut impl Layouter<F>,
        left: [AssignedCell<F, F>; I],
        right: [AssignedCell<F, F>; I],
    ) -> Result<(), Error> {
        let config = self.config();

        layouter
            .assign_region(
                || "load inputs",
                |mut region: Region<'_, F>| {
                    // pub copy layer
                    // |  value  | copy | index|  s_pub|
                    // |  left   |  *   |   *  |    0  |
                    // |  right  |  *   |   *  |    0  |
                    // |  chosen |  0   |  0/1 |    1  |
                    // ....
                    // chosen = pub1,pub2, ... pubI

                    config.s_pub.enable(&mut region, 2)?;
                    for j in 0..I {
                        left[j].copy_advice(|| "assign left", &mut region, config.value[j], 0)?;
                        right[j].copy_advice(|| "assign right", &mut region, config.value[j], 1)?;
                        region.assign_advice_from_instance(
                            || "copy selected leaf from instance",
                            config.public,
                            j,
                            config.value[j],
                            2,
                        )?;
                    }

                    region.assign_advice_from_instance(
                        || "assign index for zero layer",
                        config.public,
                        I,
                        config.index_flag,
                        2,
                    )?;

                    region.assign_advice(
                        || "assign copy",
                        config.copy_flag,
                        2,
                        || Value::known(F::ZERO),
                    )?;

                    Ok(())
                },
            )
            .unwrap();
        return Ok(());
    }
}

impl<F: PrimeField, const I: usize> Chip<F> for MerklePathChip<F, I> {
    type Config = MerklePathConfig<I>;

    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
