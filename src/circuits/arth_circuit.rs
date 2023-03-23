use super::super::chips::arth_chips::*;

use ff::PrimeField;
use halo2_proofs::circuit::{SimpleFloorPlanner, Value};
use halo2_proofs::plonk::Circuit;

#[derive(Clone)]
pub struct DemoConfig1 {
    arth_config: ArthConfig,
}

// (x^3+x)y=z
#[derive(Default)]
pub struct DemoCircuit1<F: PrimeField> {
    x: Value<F>,
}

impl<F: PrimeField> Circuit<F> for DemoCircuit1<F> {
    type Config = DemoConfig1;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        // We create the two advice columns that uses for 2 fan-in inputs.
        let advice = [meta.advice_column(), meta.advice_column()];

        // We also need an instance column to store public inputs.
        let instance = meta.instance_column();

        DemoConfig1 {
            arth_config: ArthChip::configure(meta, advice, instance),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        let chip = ArthChip::new(config.arth_config);
        let x = chip.load_private(layouter.namespace(|| "load x"), self.x)?;
        let y = chip.load_public(layouter.namespace(|| "load public"), 0)?;

        let x3 = chip.cube(layouter.namespace(|| "x2 * x"), x.clone())?;
        let x3_x = chip.add(layouter.namespace(|| "x3 + x"), x3.clone(), x.clone())?;
        let y_x3_x = chip.mul(layouter.namespace(|| "y(x3 + x)"), x3_x.clone(), y)?;

        chip.expose_public(layouter.namespace(|| "expose result"), y_x3_x, 1)
    }
}

impl<F: PrimeField> DemoCircuit1<F> {
    pub fn new(input: F) -> DemoCircuit1<F> {
        DemoCircuit1 {
            x: Value::known(input),
        }
    }
}
