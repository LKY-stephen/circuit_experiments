use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};

#[derive(Clone)]
pub struct Number<F: FieldExt> {
    value: AssignedCell<F, F>,
}

pub trait NumericInstructions<F: FieldExt>: Chip<F> {
    /// Variable representing a number.
    type Num;

    /// Loads a number into the circuit as a private input.
    fn load_private(&self, layouter: impl Layouter<F>, a: Value<F>) -> Result<Self::Num, Error>;

    /// Loads a number into the circuit as a fixed constant.
    fn load_public(&self, layouter: impl Layouter<F>, row: usize) -> Result<Self::Num, Error>;

    /// Returns `c = a * b`.
    fn mul(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error>;

    /// Returns `c = a + b`.
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error>;

    /// Returns `c = a ^ 3`.
    fn cube(&self, layouter: impl Layouter<F>, a: Self::Num) -> Result<Self::Num, Error>;

    fn expose_public(
        &self,
        layouter: impl Layouter<F>,
        num: Self::Num,
        row: usize,
    ) -> Result<(), Error>;
}

pub struct ArthChip<F: FieldExt> {
    config: ArthConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct ArthConfig {
    /// two private inputs for 2 fan in gates
    advice: [Column<Advice>; 2],

    /// This is the public input (instance) column.
    instance: Column<Instance>,

    // selectors to enable the gate
    s_mul: Selector,
    s_add: Selector,
    s_cube: Selector,
}

impl<F: FieldExt> ArthChip<F> {
    pub fn new(config: ArthConfig) -> Self {
        ArthChip {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        instance: Column<Instance>,
    ) -> <Self as Chip<F>>::Config {
        meta.enable_equality(instance);
        for column in &advice {
            meta.enable_equality(*column);
        }
        let s_mul = meta.selector();
        let s_add = meta.selector();
        let s_cube = meta.selector();

        // Define our multiplication gate!
        meta.create_gate("mul", |meta| {
            //
            // | a0  | a1  | s_mul |
            // |-----|-----|-------|
            // | lhs | rhs | s_mul |
            // | out |     |       |
            //
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_mul = meta.query_selector(s_mul);

            // Finally, we return the polynomial expressions that constrain this gate.
            // For our multiplication gate, we only need a single polynomial constraint.
            //
            // The polynomial expressions returned from `create_gate` will be
            // constrained by the proving system to equal zero. Our expression
            // has the following properties:
            // - When s_mul = 0, any value is allowed in lhs, rhs, and out.
            // - When s_mul != 0, this constrains lhs * rhs = out.
            vec![s_mul * (lhs * rhs - out)]
        });

        meta.create_gate("add", |meta| {
            //
            // | a0  | a1  | s_add |
            // |-----|-----|-------|
            // | lhs | rhs | s_add |
            // | out |     |       |

            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_add = meta.query_selector(s_add);

            vec![s_add * (lhs + rhs - out)]
        });

        meta.create_gate("cube", |meta| {
            //
            // | a0  | s_add |
            // |-----|-------|
            // | lhs | s_add |
            // | out |       |

            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_pow3 = meta.query_selector(s_cube);

            vec![s_pow3 * (lhs.clone() * lhs.clone() * lhs - out)]
        });

        ArthConfig {
            advice,
            instance,
            s_mul,
            s_add,
            s_cube,
        }
    }
}

impl<F: FieldExt> NumericInstructions<F> for ArthChip<F> {
    type Num = Number<F>;

    fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<F>,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load private",
            |mut region| {
                region
                    .assign_advice(|| "private input", config.advice[0], 0, || value)
                    .map(|x| Number { value: x })
            },
        )
    }

    fn load_public(&self, mut layouter: impl Layouter<F>, row: usize) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load public",
            |mut region| {
                region
                    .assign_advice_from_instance(
                        || "constant value",
                        config.instance,
                        row,
                        config.advice[0],
                        0,
                    )
                    .map(|x| Number { value: x })
            },
        )
    }

    fn mul(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "mul",
            |mut region: Region<'_, F>| {
                // We only want to use a single multiplication gate in this region,
                // so we enable it at region offset 0; this means it will constrain
                // cells at offsets 0 and 1.
                config.s_mul.enable(&mut region, 0)?;

                // The inputs we've been given could be located anywhere in the circuit,
                // but we can only rely on relative offsets inside this region. So we
                // assign new cells inside the region and constrain them to have the
                // same values as the inputs.
                a.value
                    .copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.value
                    .copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;

                // Now we can assign the multiplication result, which is to be assigned
                // into the output position.
                let value = a.value.value().copied() * b.value.value();

                // Finally, we do the assignment to the output, returning a
                // variable to be used in another part of the circuit.
                region
                    .assign_advice(|| "lhs * rhs", config.advice[0], 1, || value)
                    .map(|x| Number { value: x })
            },
        )
    }

    fn add(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "add",
            |mut region: Region<'_, F>| {
                // We only want to use a single adddition gate in this region,
                // so we enable it at region offset 0; this means it will constrain
                // cells at offsets 0 and 1.
                config.s_add.enable(&mut region, 0)?;

                // The inputs we've been given could be located anywhere in the circuit,
                // but we can only rely on relative offsets inside this region. So we
                // assign new cells inside the region and constrain them to have the
                // same values as the inputs.
                a.value
                    .copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.value
                    .copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;

                // Now we can assign the adddition result, which is to be assigned
                // into the output position.
                let value = a.value.value().copied() + b.value.value();

                // Finally, we do the assignment to the output, returning a
                // variable to be used in another part of the circuit.
                region
                    .assign_advice(|| "lhs + rhs", config.advice[0], 1, || value)
                    .map(|x| Number { value: x })
            },
        )
    }

    fn cube(&self, mut layouter: impl Layouter<F>, a: Self::Num) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "pow3",
            |mut region: Region<'_, F>| {
                config.s_cube.enable(&mut region, 0)?;

                a.value
                    .copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;

                let value = a.value.value().copied().to_field().cube().evaluate();

                region
                    .assign_advice(|| "lhs ^ 3", config.advice[0], 1, || value)
                    .map(|x| Number { value: x })
            },
        )
    }

    fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        num: Self::Num,
        row: usize,
    ) -> Result<(), Error> {
        let config = self.config();

        layouter.constrain_instance(num.value.cell(), config.instance, row)
    }
}

impl<F: FieldExt> Chip<F> for ArthChip<F> {
    type Config = ArthConfig;

    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
