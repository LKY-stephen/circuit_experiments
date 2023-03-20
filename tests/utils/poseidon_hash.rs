use circuit_samples::circuits::poseidon_circuit::utils::Spec;
use halo2_proofs::{arithmetic::FieldExt, circuit::Value, poly::Error};
use rand::Rng;

pub struct MerklePath<F: FieldExt> {
    left: Vec<Vec<F>>,
    right: Vec<Vec<F>>,
    index: Vec<F>,
}

/// A mirrored implementation for poseidon hash
pub fn hash<F: FieldExt, S: Spec<F, W>, const W: usize>(inputs: Vec<F>) -> Result<Vec<F>, Error> {
    // initate states [0,0,...., capacity]
    let mut states = [F::zero(); W];
    states[W - 1] = F::from_u128(S::capacity());
    let size = S::element_size();

    let elements = inputs
        .chunks(size)
        .map(|c| c.to_vec().into_iter().chain(S::pad()).collect::<Vec<_>>())
        .collect::<Vec<_>>();

    // absorb add inputs to state and then do permutation
    for x in elements {
        for i in 0..W - 1 {
            states[i] = states[i] + x[i];
        }
        states = permutation::<F, S, W>(states);
    }

    //squezze
    let results: Vec<F> = states[0..size].to_vec();
    return Ok(results);
}

fn permutation<F: FieldExt, S: Spec<F, W>, const W: usize>(input: [F; W]) -> [F; W] {
    let fr = S::full_rounds();
    let pr = S::partial_rounds();
    let all_rounds = fr + pr;
    let half_rounds = fr / 2;
    let mid = half_rounds + pr;
    let mut result = input;
    for i in 0..half_rounds {
        result = full_round::<F, S, W>(result, i);
    }
    for i in half_rounds..mid {
        result = partial_round::<F, S, W>(result, i);
    }

    for i in mid..all_rounds {
        result = full_round::<F, S, W>(result, i);
    }

    result
}

fn full_round<F: FieldExt, S: Spec<F, W>, const W: usize>(input: [F; W], round: usize) -> [F; W] {
    let ark = S::arks()[round];
    let mds = S::mds();
    // add round constant and apply full box
    let mid: Vec<F> = (0..W)
        .map(|i| {
            let x = input[i] + ark[i];
            x.clone().cube() * x.clone().square()
        })
        .collect();

    let result = (0..W)
        .map(|i| {
            (0..W)
                .map(|j| mid[j].clone() * mds[i][j])
                .reduce(|acc, x| acc + x)
                .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    return result;
}

fn partial_round<F: FieldExt, S: Spec<F, W>, const W: usize>(
    input: [F; W],
    round: usize,
) -> [F; W] {
    let ark = S::arks()[round];
    let mds = S::mds();
    // add round constant and apply full box
    let mut mid: Vec<F> = (0..W).map(|i| input[i] + ark[i]).collect();
    mid[0] = mid[0].clone().cube() * mid[0].clone().square();

    let result = (0..W)
        .map(|i| {
            (0..W)
                .map(|j| mid[j].clone() * mds[i][j])
                .reduce(|acc, x| acc + x)
                .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    return result;
}

// Generate a random merkle path with n layers and m index
// return left path, right path, index and selected leaf
pub fn gen_merkle_path<F: FieldExt, S: Spec<F, W>, const W: usize>(
    n: usize,
    m: usize,
) -> MerklePath<F> {
    let mut rng = rand::thread_rng();
    let element_size = S::element_size();
    let inputs: Vec<Vec<F>> = (0..n + 1)
        .map(|_| {
            (0..element_size)
                .map(|_| <F as FieldExt>::from_u128(rng.gen::<u128>()))
                .collect()
        })
        .collect();

    let mut left = vec![inputs[0].to_owned()];
    let mut right = vec![inputs[1].to_owned()];

    let mut index = vec![];

    match rng.gen_bool(0.5) {
        true => {
            index.push(F::one());
        }
        false => {
            index.push(F::zero());
        }
    };

    // put element size
    for i in 1..=m {
        let bit = rng.gen_bool(0.5);
        // add path
        if i < m {
            index.push(match bit {
                true => F::one(),
                false => F::zero(),
            });
        }

        if i <= n {
            let hash_inputs = left[i - 1]
                .to_owned()
                .into_iter()
                .chain(right[i - 1].to_owned())
                .collect::<Vec<_>>();
            let hash = hash::<F, S, W>(hash_inputs.clone()).unwrap();
            let element = match i < n {
                true => inputs[i + 1].to_owned(),

                // last line is duplicated
                false => hash.clone(),
            };

            match bit {
                true => {
                    right.push(hash);
                    left.push(element);
                }
                false => {
                    left.push(hash);
                    right.push(element);
                }
            };
        }
    }

    assert!(left.iter().all(|v| v.len() == element_size));
    assert!(right.iter().all(|v| v.len() == element_size));

    return MerklePath { left, right, index };
}

impl<F: FieldExt> MerklePath<F> {
    pub fn get_leaf(&self) -> Vec<F> {
        let inital_bit = self.index.first().expect("leaf index is missed").to_owned();
        if inital_bit == F::one() {
            self.right.first().expect("missing right leaf ").to_owned()
        } else if inital_bit == F::zero() {
            self.left.first().expect("missing left leaf ").to_owned()
        } else {
            panic!("leaf index is not binary");
        }
    }

    pub fn get_root(&self) -> Vec<F> {
        self.right.last().expect("missing right leaf ").to_owned()
    }

    pub fn get_index(&self) -> Vec<F> {
        self.index.clone()
    }

    pub fn get_left_value(&self) -> Vec<Vec<Value<F>>> {
        self.left
            .clone()
            .into_iter()
            .map(|v| v.into_iter().map(Value::known).collect())
            .collect::<Vec<_>>()
    }

    pub fn get_right_value(&self) -> Vec<Vec<Value<F>>> {
        self.right
            .clone()
            .into_iter()
            .map(|v| v.into_iter().map(Value::known).collect())
            .collect::<Vec<_>>()
    }

    pub fn get_copy_value(&self, m: usize) -> Vec<Value<F>> {
        let n = self.left.len();
        (0..=m)
            .map(|i| match i < n {
                true => Value::known(F::zero()),
                false => Value::known(F::one()),
            })
            .collect::<Vec<_>>()
    }
}
