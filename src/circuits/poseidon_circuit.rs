use std::marker::PhantomData;

use self::utils::Spec;

use super::super::chips::poseidon_chip::*;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};

pub mod utils;

#[derive(Clone)]
pub struct PoseidonConfig<F: FieldExt, S: Spec<F, W>, const W: usize> {
    arth_config: PoseidonArthConfig<F, W>,
    _marker: PhantomData<S>,
}

// implementation for 5-posiedon
// For each input, we fixed the padding as [x,1,0,0,...,0]
// inputs permutation rounds will go for all abosrb
#[derive(Clone, Default)]
pub struct PoseidonCircuit<F: FieldExt, S: Spec<F, W>, const W: usize> {
    x: Vec<Value<F>>,
    _marker: PhantomData<S>,
}

impl<F: FieldExt, S: Spec<F, W> + Clone + Default, const W: usize> Circuit<F>
    for PoseidonCircuit<F, S, W>
{
    type Config = PoseidonConfig<F, S, W>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let states: Vec<_> = (0..W).map(|_| meta.advice_column()).collect();
        let arks: Vec<_> = (0..W).map(|_| meta.fixed_column()).collect();

        // public column for output
        let output = meta.instance_column();

        // We also need an instance column to store public inputs.
        let mds = S::mds();
        let ark_paras = S::arks();

        PoseidonConfig {
            arth_config: PoseidonChip::configure(
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
        config: PoseidonConfig<F, S, W>,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = PoseidonChip::new(config.arth_config);
        let length = self.x.len();
        let mut state = chip.initiate(&mut layouter)?;
        let fr = S::full_rounds();
        let pr = S::partial_rounds();
        for i in 0..length {
            // pad
            let mut input = vec![self.x[i].clone()];
            input.append(&mut S::pad().into_iter().map(Value::known).collect());

            // abosrb
            state = chip.load_inputs(&mut layouter, state.clone(), &input)?;
            state = chip.permutation(&mut layouter, state, fr, pr)?;
        }

        // squeeze
        let output_size = S::squeeze_rounds();
        let mut i = 0;
        chip.expose_public(&mut layouter, state.clone(), i)?;
        while i < output_size - 1 {
            state = chip.permutation(&mut layouter, state, fr, pr)?;
            i = i + 1;
            chip.expose_public(&mut layouter, state.clone(), i)?;
        }

        return Ok(());
    }
}

impl<F: FieldExt, S: Spec<F, W>, const W: usize> PoseidonCircuit<F, S, W> {
    pub fn new(input: Vec<F>) -> PoseidonCircuit<F, S, W> {
        PoseidonCircuit {
            x: input
                .into_iter()
                .map(|x| -> Value<F> { Value::known(x) })
                .collect(),
            _marker: PhantomData,
        }
    }
}
