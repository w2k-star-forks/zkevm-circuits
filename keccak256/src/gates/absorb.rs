use crate::arith_helpers::*;
use crate::common::*;
use halo2::circuit::Cell;
use halo2::circuit::Layouter;
use halo2::circuit::Region;
use halo2::{
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use pairing::arithmetic::FieldExt;
use std::{convert::TryInto, marker::PhantomData};

#[derive(Clone, Debug)]
pub struct AbsorbConfig<F> {
    q_mixing: Selector,
    state: [Column<Advice>; 25],
    _marker: PhantomData<F>,
}

impl<F: FieldExt> AbsorbConfig<F> {
    pub const OFFSET: usize = 2;
    // We assume state is recieved in base-9.
    // Rows are assigned as:
    // 1) STATE (25 columns) (offset -1)
    // 2) NEXT_INPUTS (17 columns) + is_mixing flag (1 column) (offset +0)
    // (current rotation)
    // 3) OUT_STATE (25 columns) (offset +1)
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        state: [Column<Advice>; 25],
    ) -> AbsorbConfig<F> {
        // def absorb(state: List[List[int], next_input: List[List[int]):
        //     for x in range(5):
        //         for y in range(5):
        //             # state[x][y] has 2*a + b + 3*c already, now add 2*d to
        // make it 2*a + b + 3*c + 2*d             # coefficient in 0~8
        //             state[x][y] += 2 * next_input[x][y]
        //     return state

        // Declare the q_mixing.
        let q_mixing = meta.selector();
        state
            .iter()
            .for_each(|column| meta.enable_equality((*column).into()));

        meta.create_gate("absorb", |meta| {
            // We do a trick which consists on multiplying an internal selector
            // which is always active by the actual `is_mixing` flag
            // which will then enable or disable the gate.
            let q_enable = {
                // We query the flag value from the `state` `Advice` column at
                // rotation curr and position = `ABSORB_NEXT_INPUTS + 1`
                // and multiply to it the active selector so that we avoid the
                // `PoisonedConstraints` and each gate equation
                // can be satisfied while enforcing the correct gate logic.
                let flag = meta
                    .query_advice(state[ABSORB_NEXT_INPUTS], Rotation::cur());
                // Note also that we want to enable the gate when `is_mixing` is
                // true. (flag = 1). See the flag computation above.
                meta.query_selector(q_mixing) * flag
            };

            (0..ABSORB_NEXT_INPUTS)
                .map(|idx| {
                    let val = meta.query_advice(state[idx], Rotation::prev())
                        + (Expression::Constant(F::from(A4))
                            * meta.query_advice(state[idx], Rotation::cur()));

                    let next_lane =
                        meta.query_advice(state[idx], Rotation::next());

                    q_enable.clone() * (val - next_lane)
                })
                .collect::<Vec<_>>()
        });

        AbsorbConfig {
            q_mixing,
            state,
            _marker: PhantomData,
        }
    }

    pub fn assign_next_inp_and_flag(
        &self,
        region: &mut Region<F>,
        offset: usize,
        flag: (Cell, F),
        next_input: [F; ABSORB_NEXT_INPUTS],
    ) -> Result<(Cell, F), Error> {
        // Generate next_input in base-9.
        let mut next_mixing =
            state_to_biguint::<F, ABSORB_NEXT_INPUTS>(next_input);
        for (x, y) in (0..5).cartesian_product(0..5) {
            if x >= 3 && y >= 1 {
                break;
            }
            next_mixing[(x, y)] = convert_b2_to_b9(
                next_mixing[(x, y)].clone().try_into().unwrap(),
            )
        }
        let next_input =
            state_bigint_to_field::<F, ABSORB_NEXT_INPUTS>(next_mixing);

        // Assign next_mixing at offset = 1
        for (idx, lane) in next_input.iter().enumerate() {
            region.assign_advice(
                || format!("assign next_input {}", idx),
                self.state[idx],
                offset,
                || Ok(*lane),
            )?;
        }

        // Assign flag at last column(17th) of the offset = 1 row.
        let obtained_cell = region.assign_advice(
            || format!("assign next_input {}", ABSORB_NEXT_INPUTS),
            self.state[ABSORB_NEXT_INPUTS],
            offset,
            || Ok(flag.1),
        )?;
        region.constrain_equal(flag.0, obtained_cell)?;

        Ok((obtained_cell, flag.1))
    }

    /// Doc this
    pub fn copy_state_flag_next_inputs(
        &self,
        layouter: &mut impl Layouter<F>,
        in_state: [(Cell, F); 25],
        out_state: [F; 25],
        // Passed in base-2 and converted internally after witnessing it.
        next_input: [F; ABSORB_NEXT_INPUTS],
        flag: (Cell, F),
    ) -> Result<([(Cell, F); 25], (Cell, F)), Error> {
        layouter.assign_region(
            || "Absorb state assignations",
            |mut region| {
                let mut offset = 0;
                // State at offset + 0
                for (idx, (cell, value)) in in_state.iter().enumerate() {
                    let new_cell = region.assign_advice(
                        || format!("assign state {}", idx),
                        self.state[idx],
                        offset,
                        || Ok(*value),
                    )?;

                    region.constrain_equal(*cell, new_cell)?;
                }

                offset += 1;
                // Enable `q_mixing` at `offset + 1`
                self.q_mixing.enable(&mut region, offset)?;

                // Assign `next_inputs` and flag.
                let flag = self.assign_next_inp_and_flag(
                    &mut region,
                    offset,
                    flag,
                    next_input,
                )?;

                offset += 1;
                // Assign out_state at offset + 2
                let mut state: Vec<(Cell, F)> = Vec::with_capacity(25);
                for (idx, lane) in out_state.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("assign state {}", idx),
                        self.state[idx],
                        offset,
                        || Ok(*lane),
                    )?;
                    state.push((cell, *lane));
                }
                let out_state: [(Cell, F); 25] = state
                    .try_into()
                    .expect("Unexpected into_slice conversion err");

                Ok((out_state, flag))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::State;
    use crate::keccak_arith::KeccakFArith;
    use halo2::circuit::Layouter;
    use halo2::plonk::{Advice, Column, ConstraintSystem, Error};
    use halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
    use itertools::Itertools;
    use pairing::bn256::Fr as Fp;
    use pretty_assertions::assert_eq;
    use std::convert::TryInto;
    use std::marker::PhantomData;

    #[test]
    fn test_absorb_gate() {
        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
            next_input: [F; ABSORB_NEXT_INPUTS],
            is_mixing: bool,
            _marker: PhantomData<F>,
        }
        impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
            type Config = AbsorbConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let state: [Column<Advice>; 25] = (0..25)
                    .map(|_| {
                        let column = meta.advice_column();
                        meta.enable_equality(column.into());
                        column
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();

                AbsorbConfig::configure(meta, state)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                let val: F = (self.is_mixing as u64).into();
                let flag: (Cell, F) = layouter.assign_region(
                    || "witness_is_mixing_flag",
                    |mut region| {
                        let offset = 1;
                        let cell = region.assign_advice(
                            || "assign is_mising",
                            config.state[ABSORB_NEXT_INPUTS + 1],
                            offset,
                            || Ok(val),
                        )?;
                        Ok((cell, val))
                    },
                )?;

                // Witness `in_state`.
                let in_state: [(Cell, F); 25] = layouter.assign_region(
                    || "Witness input state",
                    |mut region| {
                        let mut state: Vec<(Cell, F)> = Vec::with_capacity(25);
                        for (idx, val) in self.in_state.iter().enumerate() {
                            let cell = region.assign_advice(
                                || "witness input state",
                                config.state[idx],
                                0,
                                || Ok(*val),
                            )?;
                            state.push((cell, *val))
                        }

                        Ok(state.try_into().unwrap())
                    },
                )?;

                config.copy_state_flag_next_inputs(
                    &mut layouter,
                    in_state,
                    self.out_state,
                    self.next_input,
                    flag,
                )?;

                Ok(())
            }
        }

        let input1: State = [
            [1, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ];

        let input2: State = [
            [2, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ];

        // Convert the input to base9 as the gadget already expects it like this
        // since it's always the output of IotaB9.
        let mut in_state = StateBigInt::from(input1);
        for (x, y) in (0..5).cartesian_product(0..5) {
            in_state[(x, y)] = convert_b2_to_b9(input1[x][y])
        }

        let in_state = state_bigint_to_field(in_state);
        let out_state = state_bigint_to_field(KeccakFArith::absorb(
            &StateBigInt::from(input1),
            &input2,
        ));

        let next_input = state_bigint_to_field(StateBigInt::from(input2));

        // With flag set to true, the gate should trigger.
        {
            // With the correct input and output witnesses, the proof should
            // pass.
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state,
                next_input: next_input,
                is_mixing: true,
                _marker: PhantomData,
            };

            let prover = MockProver::<Fp>::run(9, &circuit, vec![]).unwrap();

            assert_eq!(prover.verify(), Ok(()));

            // With wrong input and/or output witnesses, the proof should fail
            // to be verified.
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state: in_state,
                next_input: next_input,
                is_mixing: true,
                _marker: PhantomData,
            };

            let prover = MockProver::<Fp>::run(9, &circuit, vec![]).unwrap();

            assert!(prover.verify().is_err());
        }

        // With flag set to `false`, the gate shouldn't trigger.
        // And so we can pass any witness data and the proof should pass.
        {
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state: in_state,
                next_input: next_input,
                is_mixing: false,
                _marker: PhantomData,
            };

            let prover = MockProver::<Fp>::run(9, &circuit, vec![]).unwrap();

            assert_eq!(prover.verify(), Ok(()));
        }
    }
}
