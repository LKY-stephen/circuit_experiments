// Since we need to verify the hash computation
// The constraints will be an extension to the poseidon_chip's
// with additional merkle related constraints.

use std::{marker::PhantomData, vec};

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Constraints, Error,
        Expression::{self},
        Instance, Selector,
    },
    poly::Rotation,
};

#[derive(Debug, Clone)]
pub struct Node<F: FieldExt, const I: usize>([AssignedCell<F, F>; I]);

pub trait MerklePathInstruction<F: FieldExt, const I: usize>: Chip<F> {
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

pub struct MerklePathChip<F: FieldExt, const I: usize> {
    config: MerklePathConfig<I>,
    _marker: PhantomData<F>,
}

///
/// The chip handles three
#[derive(Clone, Debug)]
pub struct MerklePathConfig<const I: usize> {
    /// private input for left child
    left: [Column<Advice>; I],

    /// private input for right child
    right: [Column<Advice>; I],

    /// hash for inputs
    hash: [Column<Advice>; I],

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

impl<F: FieldExt, const I: usize> MerklePathChip<F, I> {
    pub fn new(config: MerklePathConfig<I>) -> Self {
        MerklePathChip {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        left: [Column<Advice>; I],
        right: [Column<Advice>; I],
        hash: [Column<Advice>; I],
        copy_flag: Column<Advice>,
        index_flag: Column<Advice>,
        public: Column<Instance>,
    ) -> <Self as Chip<F>>::Config {
        // equality checks for output and internal states
        for i in 0..I {
            meta.enable_equality(left[i]);
            meta.enable_equality(right[i]);
            meta.enable_equality(hash[i]);
        }

        meta.enable_equality(index_flag);

        let s_hash = meta.selector();
        let s_pub = meta.selector();

        let one = Expression::Constant(F::one());
        let bool_constraint = |v: Expression<F>| v.clone() * (one.clone() - v);

        let copy_flag_constraint =
            |before: Expression<F>, after: Expression<F>| before * (one.clone() - after);

        // constraints the hash and copy constraints
        meta.create_gate("Copy_Hash", |meta| {
            let s_hash = meta.query_selector(s_hash);

            let p_left_v = (0..I)
                .map(|i| meta.query_advice(left[i], Rotation::prev()))
                .collect::<Vec<_>>();

            let p_right_v = (0..I)
                .map(|i| meta.query_advice(right[i], Rotation::prev()))
                .collect::<Vec<_>>();

            let p_hash_v = (0..I)
                .map(|i| meta.query_advice(hash[i], Rotation::prev()))
                .collect::<Vec<_>>();

            let p_copy = meta.query_advice(copy_flag, Rotation::prev());
            let copy = meta.query_advice(copy_flag, Rotation::cur());
            let index = meta.query_advice(index_flag, Rotation::cur());

            let left_v = (0..I)
                .map(|i| meta.query_advice(left[i], Rotation::cur()))
                .collect::<Vec<_>>();

            let right_v = (0..I)
                .map(|i| meta.query_advice(right[i], Rotation::cur()))
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
                bool_constraint(p_copy.clone()),
                bool_constraint(copy.clone()),
                copy_flag_constraint(p_copy.clone(), copy.clone()),
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

            let left_v = (0..I)
                .map(|i| meta.query_advice(left[i], Rotation::cur()))
                .collect::<Vec<_>>();

            let right_v = (0..I)
                .map(|i| meta.query_advice(right[i], Rotation::cur()))
                .collect::<Vec<_>>();

            let hash_v = (0..I)
                .map(|i| meta.query_advice(hash[i], Rotation::cur()))
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
            left,
            right,
            hash,
            public,
            copy_flag,
            index_flag,
            s_hash,
            s_pub,
        }
    }
}

impl<F: FieldExt, const I: usize> MerklePathInstruction<F, I> for MerklePathChip<F, I> {
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
                // from row 1 till n-1, we do hash for each round, inputs our hash
                //
                // | left  | right   |  hash  | copy | index|
                // | left1 | right1  | hash1  |  0   |  1   |
                // | left2 | right2  | hash2  |  0   |  0   |
                // ....
                // hash(i) =  left(i+1) if index =0 else right(i+1)

                for i in 0..n {
                    for j in 0..I {
                        left[i][j].copy_advice(|| "assign left", &mut region, config.left[j], i)?;
                        right[i][j].copy_advice(
                            || "assign right",
                            &mut region,
                            config.right[j],
                            i,
                        )?;
                        hash[i][j].copy_advice(|| "copy hash", &mut region, config.hash[j], i)?;
                    }

                    region.assign_advice_from_instance(
                        || "assign index",
                        config.public,
                        I + i,
                        config.index_flag,
                        i,
                    )?;

                    config.s_hash.enable(&mut region, i + 1)?;

                    region.assign_advice(|| "assign copy", config.copy_flag, i, || copy[i])?;
                }

                // after the pathes are handled, we need to process root
                //
                // | left  | right   |    hash    | copy | index|
                // | root  | root    | root_hash  |  1   |  1   |
                // | root  | root    | root_hash  |  1   |  0   |
                // ....
                for i in n..m {
                    for j in 0..I {
                        left[i][j].copy_advice(|| "assign left", &mut region, config.left[j], i)?;
                        right[i][j].copy_advice(
                            || "assign right",
                            &mut region,
                            config.right[j],
                            i,
                        )?;
                        hash[i][j].copy_advice(|| "copy hash", &mut region, config.hash[j], i)?;
                    }

                    region.assign_advice_from_instance(
                        || "assign index",
                        config.public,
                        I + i,
                        config.index_flag,
                        i,
                    )?;

                    config.s_hash.enable(&mut region, i)?;

                    region.assign_advice(|| "assign copy", config.copy_flag, i, || copy[i])?;
                }

                // finally we put two roots at row m+1
                //
                // | left  | right   |    hash    | copy | index|
                // | root  | root    | root_hash  |  1   |   -  |
                // ....
                let root = (0..I)
                    .map(|j| {
                        let left_v = left[m][j]
                            .copy_advice(|| "assign left", &mut region, config.left[j], m)
                            .expect("failed to get left root value");
                        // right is just a copy
                        left[m][j]
                            .copy_advice(|| "assign right", &mut region, config.right[j], m)
                            .expect("failed to get right root value");
                        // hash field is useless, but we assign a random value for query
                        region
                            .assign_advice(
                                || "assign dump hash",
                                config.hash[j],
                                m,
                                || Value::known(F::one()),
                            )
                            .expect("failed to assign hash");
                        return left_v;
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("Failed to compute root");
                region.assign_advice(|| "assign copy", config.copy_flag, m, || copy[m])?;

                // index is not needed now, but we kept them for the
                // bool constraint

                region.assign_advice(
                    || "assign index",
                    config.index_flag,
                    m,
                    || Value::known(F::one()),
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
                    // | left | right |  hash  | copy | index| instance|
                    // | left | right | chosen |  0   |  *   |  pub1 |
                    // | left | right | hash   |  0   |  *   |  pub2 |
                    // ....
                    // chosen = pub1,pub2, ... pubI

                    config.s_pub.enable(&mut region, 0)?;
                    for j in 0..I {
                        left[j].copy_advice(|| "assign left", &mut region, config.left[j], 0)?;
                        right[j].copy_advice(|| "assign right", &mut region, config.right[j], 0)?;
                        region.assign_advice_from_instance(
                            || "copy selected leaf from instance",
                            config.public,
                            j,
                            config.hash[j],
                            0,
                        )?;
                    }

                    region.assign_advice_from_instance(
                        || "assign index for zero layer",
                        config.public,
                        I,
                        config.index_flag,
                        0,
                    )?;
                    region.assign_advice(
                        || "assign copy",
                        config.copy_flag,
                        0,
                        || Value::known(F::zero()),
                    )?;

                    Ok(())
                },
            )
            .unwrap();
        return Ok(());
    }
}

impl<F: FieldExt, const I: usize> Chip<F> for MerklePathChip<F, I> {
    type Config = MerklePathConfig<I>;

    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
