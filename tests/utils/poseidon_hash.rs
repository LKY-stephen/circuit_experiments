use circuit_samples::circuits::poseidon_circuit::utils::Spec;
use halo2_proofs::{arithmetic::FieldExt, poly::Error};

/// A mirrored implementation for poseidon hash
pub fn hash<F: FieldExt, S: Spec<F, W>, const W: usize>(inputs: Vec<F>) -> Result<Vec<F>, Error> {
    // initate states [0,0,...., capacity]
    let mut states = [F::zero(); W];
    states[W - 1] = F::from_u128(S::capacity());

    // absorb add [x, pad[0], ...,pad[W-2]] to state and then do permutation
    for x in inputs {
        let padded: Vec<F> = vec![x].into_iter().chain(S::pad()).collect::<Vec<_>>();
        for i in 0..W - 1 {
            states[i] = states[i] + padded[i];
        }
        states = permutation::<F, S, W>(states);
    }

    //squezze
    let output_size = S::squeeze_rounds();
    let mut results: Vec<F> = vec![states[0]];
    for _ in 0..output_size - 1 {
        states = permutation::<F, S, W>(states);
        results.push(states[0]);
    }
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
