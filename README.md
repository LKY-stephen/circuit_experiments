# circuit Samples
A repo for writing some circuits of halo2
1. Demo circuit DemoCircuit1: $(x^3+x)y=z$
2. Poseidon hash circuit
    The implementation refers to halo2_gadget with a more straightforward architecture. The flow of the poseidon hash can refer to [here](./tests/utils/poseidon_hash.rs).
3. merkla path verification. Given a leaf, a path of m steps, and a root, proof their is a path following the first n steps from the leaf till the root.