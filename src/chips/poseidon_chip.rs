use std::{marker::PhantomData, vec};

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};

#[derive(Clone)]
pub struct States<F: FieldExt, const WIDTH: usize>([Data<F>; WIDTH]);

#[derive(Debug, Clone)]
pub struct Data<F: FieldExt>(AssignedCell<F, F>);

pub trait PoseidonInstructions<F: FieldExt, const WIDTH: usize>: Chip<F> {
    /// Variable representing a value.
    type Data;

    /// Variable representing internal states.
    type State;

    /// Loads a number into the circuit as a private input.
    fn initiate(&self, layouter: &mut impl Layouter<F>) -> Result<Self::State, Error>;

    /// Loads a number into the circuit as a private input.
    fn load_inputs(
        &self,
        layouter: &mut impl Layouter<F>,
        states: Self::State,
        inputs: &Vec<Value<F>>,
    ) -> Result<Self::State, Error>;

    // permutation with given number of full rounds and partial rounds
    fn permutation(
        &self,
        layouter: &mut impl Layouter<F>,
        states: Self::State,
        full_round: usize,
        partial_round: usize,
    ) -> Result<Self::State, Error>;

    /// Return s[0]==output[0];
    fn expose_public(
        &self,
        layouter: &mut impl Layouter<F>,
        states: Self::State,
        round: usize,
    ) -> Result<(), Error>;
}

pub struct PoseidonChip<F: FieldExt, const WIDTH: usize> {
    config: PoseidonArthConfig<F, WIDTH>,
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct PoseidonArthConfig<F: FieldExt, const WIDTH: usize> {
    /// one private input for states
    state: [Column<Advice>; WIDTH],

    // two fixed colum for arc parameters and mds
    arc: [Column<Fixed>; WIDTH],

    /// This is the public input (instance) column.
    output: Column<Instance>,

    // selectors to enable the gate
    s_fbox: Selector,
    s_pbox: Selector,
    s_add_inputs: Selector,

    // const parameters
    arc_paras: Vec<[F; WIDTH]>,
    mds: [[F; WIDTH]; WIDTH],
    capacity: u128,
}

impl<F: FieldExt, const WIDTH: usize> PoseidonChip<F, WIDTH> {
    pub fn new(config: PoseidonArthConfig<F, WIDTH>) -> Self {
        PoseidonChip {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        state: [Column<Advice>; WIDTH],
        output: Column<Instance>,
        arc: [Column<Fixed>; WIDTH],
        mds: [[F; WIDTH]; WIDTH],
        arc_paras: Vec<[F; WIDTH]>,
        capacity: u128,
    ) -> <Self as Chip<F>>::Config {
        // equality checks for output and internal states
        meta.enable_equality(output);
        for column in &state {
            meta.enable_equality(*column);
        }

        let s_fbox = meta.selector();
        let s_pbox = meta.selector();
        let s_add_inputs = meta.selector();

        let pow_5 = |v: Expression<F>| {
            let v2 = v.clone() * v.clone();
            v2.clone() * v2 * v
        };

        let mix = |v: Vec<Expression<F>>, i: usize| {
            (0..WIDTH)
                .map(|j| v[j].clone() * mds[i][j].clone())
                .reduce(|acc, f| acc + f)
                .unwrap()
        };

        // pad WIDTH-1 inputs and copy the last input
        meta.create_gate("add-inputs", |meta| {
            let pos = WIDTH - 1;
            let initial_state_rate = meta.query_advice(state[pos], Rotation::prev());
            let output_state_rate = meta.query_advice(state[pos], Rotation::next());

            let s_add_inputs = meta.query_selector(s_add_inputs);

            let pad_and_add = |idx: usize| {
                let initial_state = meta.query_advice(state[idx], Rotation::prev());
                let input = meta.query_advice(state[idx], Rotation::cur());
                let output_state = meta.query_advice(state[idx], Rotation::next());

                // We pad the input by storing the required padding in fixed columns and
                // then constraining the corresponding input columns to be equal to it.
                initial_state + input - output_state
            };

            Constraints::with_selector(
                s_add_inputs,
                (0..pos)
                    .map(pad_and_add)
                    // The capacity element is never altered by the input.
                    .chain(Some(initial_state_rate - output_state_rate))
                    .collect::<Vec<_>>(),
            )
        });

        // Apply full round over the states
        meta.create_gate("full box", |meta| {
            let states: Vec<Expression<F>> = (0..WIDTH)
                .map(|i| meta.query_advice(state[i], Rotation::cur()))
                .collect();
            let next_states: Vec<Expression<F>> = (0..WIDTH)
                .map(|i| meta.query_advice(state[i], Rotation::next()))
                .collect();
            let arcs: Vec<Expression<F>> = (0..WIDTH)
                .map(|i| meta.query_fixed(arc[i], Rotation::cur()))
                .collect();

            let s_fbox = meta.query_selector(s_fbox);

            // (s[i]+arc[i])^5
            let mid: Vec<Expression<F>> = (0..WIDTH)
                .map(|i| pow_5(states[i].clone() + arcs[i].clone()))
                .collect();

            (0..WIDTH).map(move |i| s_fbox.clone() * (mix(mid.clone(), i) - next_states[i].clone()))
        });

        // Apply partial round over the states
        meta.create_gate("partial box", |meta| {
            let states: Vec<Expression<F>> = (0..WIDTH)
                .map(|i| meta.query_advice(state[i], Rotation::cur()))
                .collect();
            let next_states: Vec<Expression<F>> = (0..WIDTH)
                .map(|i| meta.query_advice(state[i], Rotation::next()))
                .collect();
            let arcs: Vec<Expression<F>> = (0..WIDTH)
                .map(|i| meta.query_fixed(arc[i], Rotation::cur()))
                .collect();
            let s_pbox = meta.query_selector(s_pbox);
            let mut mid = vec![pow_5(states[0].clone() + arcs[0].clone())];
            mid.append(
                &mut (1..WIDTH)
                    .map(|i| states[i].clone() + arcs[i].clone())
                    .collect(),
            );

            (0..WIDTH).map(move |i| s_pbox.clone() * (mix(mid.clone(), i) - next_states[i].clone()))
        });

        PoseidonArthConfig {
            state,
            arc,
            output,
            s_fbox,
            s_pbox,
            s_add_inputs,
            mds,
            arc_paras,
            capacity,
        }
    }
}

impl<F: FieldExt, const WIDTH: usize> PoseidonInstructions<F, WIDTH> for PoseidonChip<F, WIDTH> {
    type Data = Data<F>;

    type State = States<F, WIDTH>;

    fn initiate(&self, layouter: &mut impl Layouter<F>) -> Result<Self::State, Error> {
        let config = self.config();
        let rate = WIDTH - 1;
        let mut init = vec![F::zero(); rate];

        // capacity element
        init.push(F::from_u128(config.capacity));
        let states = layouter
            .assign_region(
                || "initiate states",
                |mut region| {
                    let state: Vec<Data<F>> = (0..WIDTH)
                        .map(|i| {
                            region
                                .assign_advice(
                                    || format!("initial state {i}"),
                                    config.state[i],
                                    0,
                                    || Value::known(init[i]),
                                )
                                .unwrap()
                        })
                        .map(Data)
                        .collect();
                    return Ok(States(state.try_into().unwrap()));
                },
            )
            .unwrap();

        Ok(states)
    }

    fn load_inputs(
        &self,
        layouter: &mut impl Layouter<F>,
        states: Self::State,
        inputs: &Vec<Value<F>>,
    ) -> Result<Self::State, Error> {
        let config = self.config();

        let rate = WIDTH - 1;
        // padding are done at circuit layer
        assert_eq!(inputs.len(), rate);

        layouter.assign_region(
            || "load inputs",
            |mut region: Region<'_, F>| {
                config.s_add_inputs.enable(&mut region, 1)?;

                for i in 0..WIDTH {
                    states.0[i].0.copy_advice(
                        || format!("load state {i}"),
                        &mut region,
                        config.state[i],
                        0,
                    )?;
                }

                let mut results: Vec<Data<F>> = Vec::with_capacity(WIDTH);
                for i in 0..rate {
                    region.assign_advice(
                        || format!("load inputs {i}"),
                        config.state[i],
                        1,
                        || inputs[i],
                    )?;

                    results.push(Data(region.assign_advice(
                        || format!("load outputs {i}"),
                        config.state[i],
                        2,
                        || states.0[i].0.value().copied() + inputs[i],
                    )?));
                }

                results.push(Data(region.assign_advice(
                    || format!("load outputs {rate}"),
                    config.state[rate],
                    2,
                    || states.0[rate].0.value().copied(),
                )?));

                Ok(States(results.try_into().unwrap()))
            },
        )
    }

    fn permutation(
        &self,
        layouter: &mut impl Layouter<F>,
        states: Self::State,
        full_round: usize,
        partial_round: usize,
    ) -> Result<Self::State, Error> {
        let config = self.config();
        // 0~half full round
        // half ~ mid partial round
        // mid~
        let half_rounds = full_round / 2;
        let mid = half_rounds + partial_round;
        let all = full_round + partial_round;

        // each round result
        let mut round_output = [Value::default(); WIDTH];

        let output_state = layouter.assign_region(
            || "permutation",
            |mut region: Region<'_, F>| {
                // store middle results
                let mut temp = [Value::default(); WIDTH];
                let mut outputs: Vec<Data<F>> = vec![];

                let pbox = |x: Value<F>| x * x * x * x * x;
                // copy advices from previous state.
                for i in 0..WIDTH {
                    states.0[i].0.copy_advice(
                        || format!("full round load state {i}"),
                        &mut region,
                        config.state[i],
                        0,
                    )?;
                    round_output[i] = states.0[i].0.value().copied();
                }
                for r in 0..all {
                    let arc = config.arc_paras[r];

                    // fill in fixed column
                    for i in 0..WIDTH {
                        region.assign_fixed(
                            || format!("round arcs {r}-{i}"),
                            config.arc[i],
                            r,
                            || Value::known(arc[i].clone()),
                        )?;

                        temp[i] = round_output[i] + Value::known(arc[i].clone());
                    }

                    if r < half_rounds || r >= mid {
                        // full rounds
                        config.s_fbox.enable(&mut region, r)?;
                        temp = temp
                            .into_iter()
                            .map(|x| pbox(x))
                            .collect::<Vec<_>>()
                            .try_into()
                            .unwrap();
                    } else {
                        // partial rounds
                        config.s_pbox.enable(&mut region, r)?;
                        temp[0] = pbox(temp[0]);
                    }

                    // apply mds
                    for i in 0..WIDTH {
                        let mut sum = Value::known(F::zero());
                        for j in 0..WIDTH {
                            sum = sum + temp[j] * Value::known(config.mds[i][j].clone());
                        }
                        round_output[i] = sum;

                        // fill in next row
                        if outputs.len() < WIDTH {
                            outputs.push(Data(
                                region
                                    .assign_advice(
                                        || format!("round output {r}-{i}"),
                                        config.state[i],
                                        r + 1,
                                        || round_output[i],
                                    )
                                    .unwrap(),
                            ));
                        } else {
                            outputs[i] = Data(
                                region
                                    .assign_advice(
                                        || format!("round output {r}-{i}"),
                                        config.state[i],
                                        r + 1,
                                        || round_output[i],
                                    )
                                    .unwrap(),
                            );
                        }
                    }
                }

                Ok(States::<F, WIDTH>(outputs.clone().try_into().unwrap()))
            },
        )?;

        return Ok(output_state);
    }

    fn expose_public(
        &self,
        layouter: &mut impl Layouter<F>,
        states: Self::State,
        round: usize,
    ) -> Result<(), Error> {
        let config = self.config();

        layouter.constrain_instance(states.0[0].0.cell(), config.output, round)
    }
}

impl<F: FieldExt, const WIDTH: usize> Chip<F> for PoseidonChip<F, WIDTH> {
    type Config = PoseidonArthConfig<F, WIDTH>;

    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
