use super::super::arith_helpers::*;
use super::tables::FromBase9TableConfig;
use super::{
    absorb::AbsorbConfig, iota_b13::IotaB13Config, iota_b9::IotaB9Config,
    state_conversion::StateBaseConversion,
};
use crate::common::*;
use crate::keccak_arith::KeccakFArith;
use halo2::circuit::Region;
use halo2::plonk::{Expression, Instance, Selector};
use halo2::poly::Rotation;
use halo2::{
    circuit::{Cell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use pairing::arithmetic::FieldExt;
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub struct MixingConfig<F> {
    iota_b9_config: IotaB9Config<F>,
    iota_b13_config: IotaB13Config<F>,
    absorb_config: AbsorbConfig<F>,
    base_conv_config: StateBaseConversion<F>,
    state: [Column<Advice>; 25],
    flag: Column<Advice>,
    q_flag: Selector,
    q_out_copy: Selector,
    out_mixing: [Column<Advice>; 25],
}

impl<F: FieldExt> MixingConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        table: FromBase9TableConfig<F>,
        round_ctant_b9: Column<Advice>,
        round_ctant_b13: Column<Advice>,
        round_constants_b9: Column<Instance>,
        round_constants_b13: Column<Instance>,
    ) -> MixingConfig<F> {
        // Allocate space for the flag column from which we will copy to all of
        // the sub-configs.
        let flag = meta.advice_column();
        meta.enable_equality(flag.into());

        // Generate a selector that will always be active to avoid the
        // PoisonedConstraint err due to no selectors being used in a
        // constraint.
        let q_flag = meta.selector();

        meta.create_gate("Ensure flag consistency", |meta| {
            let q_flag = meta.query_selector(q_flag);

            let negated_flag = meta.query_advice(flag, Rotation::next());
            let flag = meta.query_advice(flag, Rotation::cur());
            // We do a trick which consists on multiplying an internal selector
            // which is always active by the actual `negated_flag`
            // which will then enable or disable the gate.
            //
            // Force that `flag + negated_flag = 1`.
            // This ensures that flag = !negated_flag.
            let flag_consistency = (flag.clone() + negated_flag.clone())
                - Expression::Constant(F::one());

            // Define bool constraint for flags.
            // Based on: `(1-flag) * flag = 0` only if `flag` is boolean.
            let bool_constraint = |flag: Expression<F>| -> Expression<F> {
                (Expression::Constant(F::one()) - flag.clone()) * flag
            };

            // Add a constraint that sums up the results of the two branches
            // constraining it to be equal to `out_state`.
            [q_flag
                * (flag_consistency
                    + bool_constraint(flag)
                    + bool_constraint(negated_flag))]
        });

        // Allocate state columns and enable copy constraints for them.
        let state: [Column<Advice>; 25] = (0..25)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column.into());
                column
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // We don't mix -> Flag = false
        let iota_b9_config = IotaB9Config::configure(
            meta,
            state,
            round_ctant_b9,
            round_constants_b9,
        );
        // We mix -> Flag = true
        let absorb_config = AbsorbConfig::configure(meta, state);

        let base_info = table.get_base_info(false);
        let base_conv_config =
            StateBaseConversion::configure(meta, state, base_info, flag);

        let iota_b13_config = IotaB13Config::configure(
            meta,
            state,
            round_ctant_b13,
            round_constants_b13,
        );

        // Allocate out_mixing columns and enable copy constraints for them.
        // Offset = 0 (Non mixing)
        // Offset = 1 (Mixing)
        let out_mixing: [Column<Advice>; 25] = (0..25)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column.into());
                column
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let q_out_copy = meta.selector();

        meta.create_gate("Mixing result copies and constraints", |meta| {
            let q_enable = meta.query_selector(q_out_copy);
            // Add out mixing states together multiplied by the mixing_flag.
            let negated_flag = meta.query_advice(flag, Rotation::next());
            let flag = meta.query_advice(flag, Rotation::cur());

            // Multiply by flag and negated_flag the out mixing results.
            let left_side = meta.query_advice(out_mixing[0], Rotation::cur())
                * negated_flag;
            let right_side =
                meta.query_advice(out_mixing[0], Rotation::next()) * flag;
            let out_state = meta.query_advice(state[0], Rotation::cur());

            // We add the results of the mixing gate if/else branches multiplied
            // by it's corresponding flags so that we always
            // copy from the same place on the copy_constraints while enforcing
            // the equality with the out_state of the permutation.
            [q_enable * ((left_side + right_side) - out_state)]
        });

        MixingConfig {
            iota_b9_config,
            iota_b13_config,
            absorb_config,
            base_conv_config,
            state,
            flag,
            q_flag,
            q_out_copy,
            out_mixing,
        }
    }

    /// Enforce flag constraints
    pub fn enforce_flag_consistency(
        &self,
        layouter: &mut impl Layouter<F>,
        flag_bool: bool,
    ) -> Result<((Cell, F), (Cell, F)), Error> {
        layouter.assign_region(
            || "Flag and Negated flag assignation",
            |mut region| {
                self.q_flag.enable(&mut region, 0)?;
                // Witness `is_mixing` flag
                let cell = region.assign_advice(
                    || "witness is_mixing",
                    self.flag,
                    0,
                    || Ok(F::from(flag_bool as u64)),
                )?;
                let flag = (cell, F::from(flag_bool as u64));

                // Witness negated `is_mixing` flag
                let cell = region.assign_advice(
                    || "witness is_mixing",
                    self.flag,
                    1,
                    || Ok(F::from(!flag_bool as u64)),
                )?;

                Ok((flag, (cell, F::from(!flag_bool as u64))))
            },
        )
    }

    /// Enforce flag constraints
    pub fn assign_out_mixing_states(
        &self,
        layouter: &mut impl Layouter<F>,
        flag_bool: bool,
        flag: (Cell, F),
        negated_flag: (Cell, F),
        out_mixing_circ: [(Cell, F); 25],
        out_non_mixing_circ: [(Cell, F); 25],
        out_state: [F; 25],
    ) -> Result<[(Cell, F); 25], Error> {
        layouter.assign_region(
            || "Out Mixing states assignation",
            |mut region| {
                // Enable selector
                self.q_out_copy.enable(&mut region, 0)?;

                // Copy constrain flags.
                let _flag_cell = region.assign_advice(
                    || "witness is_mixing",
                    self.flag,
                    0,
                    || Ok(F::from(flag_bool as u64)),
                )?;
                region.constrain_equal(_flag_cell, flag.0)?;

                let _neg_flag_cell = region.assign_advice(
                    || "witness is_mixing",
                    self.flag,
                    1,
                    || Ok(F::from(!flag_bool as u64)),
                )?;
                region.constrain_equal(_neg_flag_cell, negated_flag.0)?;

                // TODO: Can just constraint directly without out_state passed
                self.copy_state(
                    &mut region,
                    0,
                    self.out_mixing,
                    split_state_cells(out_non_mixing_circ),
                    out_non_mixing_circ,
                )?;

                self.copy_state(
                    &mut region,
                    1,
                    self.out_mixing,
                    split_state_cells(out_mixing_circ),
                    out_mixing_circ,
                )?;

                let out_state: [(Cell, F); 25] = {
                    let mut out_vec: Vec<(Cell, F)> = vec![];
                    for (idx, lane) in out_state.iter().enumerate() {
                        let out_cell = region.assign_advice(
                            || format!("assign out_state [{}]", idx),
                            self.state[idx],
                            0,
                            || Ok(*lane),
                        )?;
                        out_vec.push((out_cell, *lane));
                    }
                    out_vec.try_into().unwrap()
                };

                Ok(out_state)
            },
        )
    }

    pub fn assign_state(
        &self,
        layouter: &mut impl Layouter<F>,
        in_state: [(Cell, F); 25],
        out_state: [F; 25],
        flag_bool: bool,
        next_mixing: Option<[F; ABSORB_NEXT_INPUTS]>,
        absolute_row: usize,
    ) -> Result<[(Cell, F); 25], Error> {
        // Enforce flag constraints and witness them.
        let (flag, negated_flag) =
            self.enforce_flag_consistency(layouter, flag_bool)?;

        // If we don't mix:
        // IotaB9
        let non_mix_res = {
            let out_state_iota_b9: [F; 25] =
                state_bigint_to_field(KeccakFArith::iota_b9(
                    &state_to_biguint(split_state_cells(in_state)),
                    *ROUND_CONSTANTS.last().unwrap(),
                ));

            self.iota_b9_config.last_round(
                layouter,
                in_state,
                out_state_iota_b9,
                absolute_row,
                flag,
            )
        }?;

        // If we mix:
        // Absorb
        let (out_state_absorb_cells, _) =
            self.absorb_config.copy_state_flag_next_inputs(
                layouter,
                in_state,
                // Compute out_absorb state.
                state_bigint_to_field(KeccakFArith::absorb(
                    &state_to_biguint(split_state_cells(in_state)),
                    &state_to_state_bigint::<F, ABSORB_NEXT_INPUTS>(
                        next_mixing.unwrap_or_default(),
                    ),
                )),
                next_mixing.unwrap_or_default(),
                flag,
            )?;

        // Base conversion assign
        let base_conv_cells = self.base_conv_config.assign_region(
            layouter,
            out_state_absorb_cells,
            flag,
        )?;

        // IotaB13
        let mix_res = {
            let out_iota_b13_state: [F; 25] =
                state_bigint_to_field(KeccakFArith::iota_b13(
                    &state_to_biguint(split_state_cells(base_conv_cells)),
                    *ROUND_CONSTANTS.last().unwrap(),
                ));

            self.iota_b13_config.copy_state_flag_and_assing_rc(
                layouter,
                base_conv_cells,
                out_iota_b13_state,
                absolute_row,
                flag,
            )
        }?;

        self.assign_out_mixing_states(
            layouter,
            flag_bool,
            flag,
            negated_flag,
            mix_res,
            non_mix_res,
            out_state,
        )
    }

    /// Copies the `[(Cell,F);25]` to the passed [Column<Advice>; 25].
    fn copy_state(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        columns: [Column<Advice>; 25],
        state_outside: [F; 25],
        state: [(Cell, F); 25],
    ) -> Result<(), Error> {
        for (idx, (out_circ_value, (in_cell, _))) in
            state_outside.iter().zip(state).enumerate()
        {
            let new_cell = region.assign_advice(
                || format!("Copy state {}", idx),
                columns[idx],
                offset,
                || Ok(*out_circ_value),
            )?;

            region.constrain_equal(in_cell, new_cell)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{State, PERMUTATION, ROUND_CONSTANTS};
    use crate::gates::gate_helpers::biguint_to_f;
    use halo2::circuit::Layouter;
    use halo2::plonk::{ConstraintSystem, Error};
    use halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
    use itertools::Itertools;
    use pairing::bn256::Fr as Fp;
    use pretty_assertions::assert_eq;
    use std::convert::TryInto;

    #[test]
    fn test_mixing_gate() {
        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
            next_mixing: Option<[F; ABSORB_NEXT_INPUTS]>,
            // This usize is indeed pointing the exact row of the
            // ROUND_CTANTS we want to use.
            round_ctant: usize,
            // flag
            is_mixing: bool,
        }

        #[derive(Clone)]
        struct MyConfig<F> {
            mixing_conf: MixingConfig<F>,
            table: FromBase9TableConfig<F>,
        }

        impl<F: FieldExt> MyConfig<F> {
            pub fn load(
                &self,
                layouter: &mut impl Layouter<F>,
            ) -> Result<(), Error> {
                self.table.load(layouter)?;
                Ok(())
            }
        }

        impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
            type Config = MyConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let table = FromBase9TableConfig::configure(meta);
                // Allocate space for the round constants in base-9 which is an
                // instance column
                let round_ctant_b9 = meta.advice_column();
                meta.enable_equality(round_ctant_b9.into());
                let round_constants_b9 = meta.instance_column();

                // Allocate space for the round constants in base-13 which is an
                // instance column
                let round_ctant_b13 = meta.advice_column();
                meta.enable_equality(round_ctant_b13.into());
                let round_constants_b13 = meta.instance_column();

                MyConfig {
                    mixing_conf: MixingConfig::configure(
                        meta,
                        table.clone(),
                        round_ctant_b9,
                        round_ctant_b13,
                        round_constants_b9,
                        round_constants_b13,
                    ),
                    table,
                }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                // Load the table
                config.table.load(&mut layouter)?;
                let offset: usize = 0;

                let in_state = layouter.assign_region(
                    || "Mixing Wittnes assignation",
                    |mut region| {
                        // Witness `in_state`
                        let in_state: [(Cell, F); 25] = {
                            let mut state: Vec<(Cell, F)> =
                                Vec::with_capacity(25);
                            for (idx, val) in self.in_state.iter().enumerate() {
                                let cell = region.assign_advice(
                                    || "witness input state",
                                    config.mixing_conf.state[idx],
                                    offset,
                                    || Ok(*val),
                                )?;
                                state.push((cell, *val))
                            }
                            state.try_into().unwrap()
                        };

                        Ok(in_state)
                    },
                )?;

                let _ = config.mixing_conf.assign_state(
                    &mut layouter,
                    in_state,
                    self.out_state,
                    self.is_mixing,
                    self.next_mixing,
                    self.round_ctant,
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

        // Convert the next_input_b9 to base9 as it needs to be added to the
        // state in base9 too.
        let next_input = StateBigInt::from(input2);

        // Compute out mixing state (when flag = 1)
        let out_mixing_state = state_bigint_to_field(KeccakFArith::mixing(
            &in_state,
            Some(&input2),
            *ROUND_CONSTANTS.last().unwrap(),
        ));

        // Compute out non-mixing state (when flag = 0)
        let out_non_mixing_state = state_bigint_to_field(KeccakFArith::mixing(
            &in_state,
            None,
            *ROUND_CONSTANTS.last().unwrap(),
        ));

        // Add inputs in the correct format.
        let in_state = state_bigint_to_field(StateBigInt::from(input1));
        let next_mixing =
            Some(state_bigint_to_field(StateBigInt::from(next_input)));

        // Compute round constants in the correct base.
        let constants_b13: Vec<Fp> = ROUND_CONSTANTS
            .iter()
            .map(|num| biguint_to_f(&convert_b2_to_b13(*num)))
            .collect();

        let constants_b9: Vec<Fp> = ROUND_CONSTANTS
            .iter()
            .map(|num| biguint_to_f(&convert_b2_to_b9(*num)))
            .collect();

        // With flag set to false, we don't mix. And so we should obtain Absorb
        // + base_conv + IotaB13 result
        {
            // With the correct input and output witnesses, the proof should
            // pass.
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state: out_mixing_state,
                next_mixing,
                is_mixing: true,
                round_ctant: PERMUTATION - 1,
            };

            let prover = MockProver::<Fp>::run(
                17,
                &circuit,
                vec![constants_b9.clone(), constants_b13.clone()],
            )
            .unwrap();

            assert_eq!(prover.verify(), Ok(()));

            // With wrong input and/or output witnesses, the proof should fail
            // to be verified.
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state: out_non_mixing_state,
                next_mixing,
                is_mixing: true,
                round_ctant: PERMUTATION - 1,
            };

            let prover = MockProver::<Fp>::run(
                17,
                &circuit,
                vec![constants_b9.clone(), constants_b13.clone()],
            )
            .unwrap();

            assert!(prover.verify().is_err());
        }

        // With flag set to `false`, we don't mix. And so we should obtain
        // IotaB9 application as result.
        {
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state: out_non_mixing_state,
                next_mixing: None,
                is_mixing: false,
                round_ctant: PERMUTATION - 1,
            };

            let prover = MockProver::<Fp>::run(
                17,
                &circuit,
                vec![constants_b9.clone(), constants_b13.clone()],
            )
            .unwrap();

            assert_eq!(prover.verify(), Ok(()));

            // With wrong input and/or output witnesses, the proof should fail
            // to be verified.
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state: in_state,
                next_mixing,
                is_mixing: false,
                round_ctant: PERMUTATION - 1,
            };

            let prover = MockProver::<Fp>::run(
                17,
                &circuit,
                vec![constants_b9, constants_b13],
            )
            .unwrap();

            assert!(prover.verify().is_err());
        }
    }
}
