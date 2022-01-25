use super::gates::{
    iota_b9::IotaB9Config, pi::pi_gate_permutation, rho::RhoConfig,
    state_conversion::StateBaseConversion, tables::FromBase9TableConfig,
    theta::ThetaConfig, xi::XiConfig,
};
use crate::gates::gate_helpers::*;
use crate::{
    arith_helpers::*,
    common::{ABSORB_NEXT_INPUTS, PERMUTATION, ROUND_CONSTANTS},
    gates::rho_checks::RhoAdvices,
};
use crate::{gates::mixing::MixingConfig, keccak_arith::*};
use halo2::{
    circuit::{Cell, Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use num_bigint::BigUint;
use pairing::arithmetic::FieldExt;
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub struct KeccakFConfig<F: FieldExt> {
    theta_config: ThetaConfig<F>,
    rho_config: RhoConfig<F>,
    xi_config: XiConfig<F>,
    iota_b9_config: IotaB9Config<F>,
    base_conversion_config: StateBaseConversion<F>,
    mixing_config: MixingConfig<F>,
    state: [Column<Advice>; 25],
    q_out: Selector,
    _is_mixing_flag: Column<Advice>,
    _base_conv_activator: Column<Advice>,
}

impl<F: FieldExt> KeccakFConfig<F> {
    // We assume state is recieved in base-9.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        table: FromBase9TableConfig<F>,
    ) -> KeccakFConfig<F> {
        let state = (0..25)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column.into());
                column
            })
            .collect_vec()
            .try_into()
            .unwrap();

        // Allocate space for the Advice column that activates the base
        // conversion during the `PERMUTATION - 1` rounds.
        let _is_mixing_flag = meta.advice_column();
        meta.enable_equality(_is_mixing_flag.into());

        // theta
        let theta_config = ThetaConfig::configure(meta.selector(), meta, state);
        // rho
        let rho_config = {
            let cols: [Column<Advice>; 7] = state[0..7].try_into().unwrap();
            let adv = RhoAdvices::from(cols);
            let axiliary = [state[8], state[9]];

            let base13_to_9 = [
                meta.lookup_table_column(),
                meta.lookup_table_column(),
                meta.lookup_table_column(),
            ];
            let special =
                [meta.lookup_table_column(), meta.lookup_table_column()];
            RhoConfig::configure(
                meta,
                state,
                &adv,
                axiliary,
                base13_to_9,
                special,
            )
        };
        // xi
        let xi_config = XiConfig::configure(meta.selector(), meta, state);

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

        // Iotab9
        let iota_b9_config = IotaB9Config::configure(
            meta,
            state,
            round_ctant_b9,
            round_constants_b9,
        );

        // Allocate space for the activation flag of the base_conversion.
        let _base_conv_activator = meta.advice_column();
        meta.enable_equality(_base_conv_activator.into());
        // Base conversion config.
        let base_info = table.get_base_info(false);
        let base_conversion_config = StateBaseConversion::configure(
            meta,
            state,
            base_info,
            _base_conv_activator,
        );

        // Mixing will make sure that the flag is binary constrained and that
        // the out state matches the expected result.
        let mixing_config = MixingConfig::configure(
            meta,
            table,
            round_ctant_b9,
            round_ctant_b13,
            round_constants_b9,
            round_constants_b13,
        );

        // Allocate the `out state correctness` gate selector
        let q_out = meta.selector();
        // Constraint the out of the mixing gate to be equal to the out state
        // announced.
        meta.create_gate("Constraint out_state correctness", |meta| {
            (0..25usize)
                .into_iter()
                .map(|idx| {
                    let q_out = meta.query_selector(q_out);
                    let out_mixing =
                        meta.query_advice(state[idx], Rotation::cur());
                    let out_expected_state =
                        meta.query_advice(state[idx], Rotation::next());
                    q_out * (out_mixing - out_expected_state)
                })
                .collect_vec()
        });

        KeccakFConfig {
            theta_config,
            rho_config,
            xi_config,
            iota_b9_config,
            base_conversion_config,
            mixing_config,
            state,
            q_out,
            _is_mixing_flag,
            _base_conv_activator,
        }
    }

    pub fn assign_all(
        &self,
        layouter: &mut impl Layouter<F>,
        in_state: [(Cell, F); 25],
        out_state: [F; 25],
        flag: bool,
        next_mixing: Option<[F; ABSORB_NEXT_INPUTS]>,
    ) -> Result<[(Cell, F); 25], Error> {
        let mut state = in_state;

        // First 23 rounds
        for round in 0..PERMUTATION - 1 {
            // State in base-13
            // theta
            state = {
                // Apply theta outside circuit
                let out_state = KeccakFArith::theta(&state_to_biguint(
                    split_state_cells(state),
                ));
                let out_state = state_bigint_to_field(out_state);
                // assignment
                self.theta_config.assign_state(layouter, state, out_state)?
            };

            println!("Iter: {}, State after Theta: {:#?}", round, state);

            // rho
            state = {
                // assignment
                let next_state =
                    self.rho_config.assign_rotation_checks(layouter, state)?;
                next_state
            };
            // Outputs in base-9 which is what Pi requires

            // Apply Pi permutation
            state = pi_gate_permutation(state);

            // xi
            state = {
                // Apply xi outside circuit
                let out_state = KeccakFArith::xi(&state_to_biguint(
                    split_state_cells(state),
                ));
                let out_state = state_bigint_to_field(out_state);
                // assignment
                self.xi_config.assign_state(layouter, state, out_state)?
            };

            // iota_b9
            state = {
                let out_state = KeccakFArith::iota_b9(
                    &state_to_biguint(split_state_cells(state)),
                    ROUND_CONSTANTS[round],
                );
                let out_state = state_bigint_to_field(out_state);
                self.iota_b9_config
                    .not_last_round(layouter, state, out_state, round)?
            };

            // The resulting state is in Base-9 now. We now convert it to
            // base_13 which is what Theta requires again at the
            // start of the loop.
            state = {
                // TODO: That could be a Fixed column.
                // Witness 1 for the activation flag.
                let activation_flag = layouter.assign_region(
                    || "Witness activation_flag",
                    |mut region| {
                        let cell = region.assign_advice(
                            || "witness is_mixing flag",
                            self._base_conv_activator,
                            0,
                            || Ok(F::one()),
                        )?;
                        Ok((cell, F::one()))
                    },
                )?;

                for (idx, (cell, lane)) in state.iter().enumerate() {
                    println!("idx {:?} lane {:?}", idx, lane);
                }

                let out_state = self.base_conversion_config.assign_region(
                    layouter,
                    state,
                    activation_flag,
                )?;
                for (idx, lane) in out_state.iter().enumerate() {
                    assert!(
                        f_to_biguint::<F>(lane.1)
                            .lt(&BigUint::from(B13 as u64).pow(64)),
                        "index {} lane {:?}",
                        idx,
                        lane.1
                    );
                }

                out_state
            }
        }

        // Mixing step
        let mix_res = KeccakFArith::mixing(
            &state_to_biguint(split_state_cells(state)),
            next_mixing
                .and_then(|state| {
                    Some(state_to_state_bigint::<F, ABSORB_NEXT_INPUTS>(state))
                })
                .as_ref(),
            (PERMUTATION - 1).try_into().unwrap(),
        );

        let mix_res = self.mixing_config.assign_state(
            layouter,
            state,
            state_bigint_to_field(mix_res),
            flag,
            next_mixing,
            // Last round = PERMUTATION - 1
            PERMUTATION - 1,
        )?;

        self.constrain_out_state(layouter, mix_res, out_state)
    }

    pub fn constrain_out_state(
        &self,
        layouter: &mut impl Layouter<F>,
        out_mixing: [(Cell, F); 25],
        out_state: [F; 25],
    ) -> Result<[(Cell, F); 25], Error> {
        layouter.assign_region(
            || "Constraint out_state and out_mixing",
            |mut region| {
                // Enable selector at offset = 0
                self.q_out.enable(&mut region, 0)?;

                // Allocate out_mixing at offset = 0 in `state` column.
                self.copy_state(&mut region, 0, self.state, out_mixing)?;

                // Witness out_state at offset = 1 in `state` column.
                let out_state: [(Cell, F); 25] = {
                    let mut out_vec: Vec<(Cell, F)> = vec![];
                    for (idx, lane) in out_state.iter().enumerate() {
                        let out_cell = region.assign_advice(
                            || format!("assign out_state [{}]", idx),
                            self.state[idx],
                            1,
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

    /// Copies the `[(Cell,F);25]` to the passed [Column<Advice>; 25].
    fn copy_state(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        columns: [Column<Advice>; 25],
        state: [(Cell, F); 25],
    ) -> Result<(), Error> {
        for (idx, (cell, value)) in state.iter().enumerate() {
            let new_cell = region.assign_advice(
                || format!("Copy state {}", idx),
                columns[idx],
                offset,
                || Ok(*value),
            )?;

            region.constrain_equal(*cell, new_cell)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{State, ABSORB_NEXT_INPUTS, ROUND_CONSTANTS};
    use crate::gates::gate_helpers::*;
    use halo2::circuit::Layouter;
    use halo2::plonk::{ConstraintSystem, Error};
    use halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
    use pairing::bn256::Fr as Fp;
    use pretty_assertions::assert_eq;
    use std::convert::TryInto;

    #[test]
    fn test_keccak_round() {
        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
            next_mixing: Option<[F; ABSORB_NEXT_INPUTS]>,
            // flag
            is_mixing: bool,
        }

        #[derive(Clone)]
        struct MyConfig<F: FieldExt> {
            keccak_conf: KeccakFConfig<F>,
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
                MyConfig {
                    keccak_conf: KeccakFConfig::configure(meta, table.clone()),
                    table,
                }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                // Load the table
                config.load(&mut layouter)?;
                let offset: usize = 0;

                let (in_state, flag) = layouter.assign_region(
                    || "Keccak round Wittnes & flag assignation",
                    |mut region| {
                        // Witness `state`
                        let in_state: [(Cell, F); 25] = {
                            let mut state: Vec<(Cell, F)> =
                                Vec::with_capacity(25);
                            for (idx, val) in self.in_state.iter().enumerate() {
                                let cell = region.assign_advice(
                                    || "witness input state",
                                    config.keccak_conf.state[idx],
                                    offset,
                                    || Ok(*val),
                                )?;
                                state.push((cell, *val))
                            }
                            state.try_into().unwrap()
                        };

                        // Witness `is_mixing` flag
                        let val = F::from(self.is_mixing as u64);
                        let cell = region.assign_advice(
                            || "witness is_mixing",
                            config.keccak_conf._is_mixing_flag,
                            offset,
                            || Ok(val),
                        )?;

                        Ok((in_state, (cell, val)))
                    },
                )?;

                config.keccak_conf.assign_all(
                    &mut layouter,
                    in_state,
                    self.out_state,
                    self.is_mixing,
                    self.next_mixing,
                )?;
                Ok(())
            }
        }

        let in_state: State = [
            [1, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ];

        let next_input: State = [
            [2, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ];

        let mut in_state_biguint = StateBigInt::default();

        // Generate in_state as `[Fp;25]`
        let mut in_state_fp: [Fp; 25] = [Fp::zero(); 25];
        for (x, y) in (0..5).cartesian_product(0..5) {
            in_state_fp[5 * x + y] =
                biguint_to_f(&convert_b2_to_b13(in_state[x][y]));
            in_state_biguint[(x, y)] = convert_b2_to_b13(in_state[x][y]);
        }

        // Compute out_state_mix
        let mut out_state_mix = in_state_biguint.clone();
        KeccakFArith::permute_and_absorb(&mut out_state_mix, Some(&next_input));

        // Compute out_state_non_mix
        let mut out_state_non_mix = in_state_biguint.clone();
        KeccakFArith::permute_and_absorb(&mut out_state_non_mix, None);

        // Generate out_state as `[Fp;25]`
        let out_state_mix: [Fp; 25] = state_bigint_to_field(out_state_mix);
        let out_state_non_mix: [Fp; 25] =
            state_bigint_to_field(out_state_non_mix);

        // Generate next_input (tho one that is not None) in the form `[F;17]`
        // Generate next_input as `[Fp;ABSORB_NEXT_INPUTS]`
        let next_input_fp: [Fp; ABSORB_NEXT_INPUTS] =
            state_bigint_to_field(StateBigInt::from(next_input));

        let constants_b13: Vec<Fp> = ROUND_CONSTANTS
            .iter()
            .map(|num| biguint_to_f(&convert_b2_to_b13(*num)))
            .collect();

        let constants_b9: Vec<Fp> = ROUND_CONSTANTS
            .iter()
            .map(|num| biguint_to_f(&convert_b2_to_b9(*num)))
            .collect();

        // When we pass no `mixing_inputs`, we perform the full keccak round
        // ending with Mixing executing IotaB9
        {
            // With the correct input and output witnesses, the proof should
            // pass.
            let circuit = MyCircuit::<Fp> {
                in_state: in_state_fp,
                out_state: out_state_non_mix,
                next_mixing: None,
                is_mixing: false,
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
                in_state: out_state_non_mix,
                out_state: out_state_non_mix,
                next_mixing: None,
                is_mixing: true,
            };

            let prover = MockProver::<Fp>::run(
                17,
                &circuit,
                vec![constants_b9.clone(), constants_b13.clone()],
            )
            .unwrap();

            assert!(prover.verify().is_err());
        }

        // When we pass `mixing_inputs`, we perform the full keccak round ending
        // with Mixing executing Absorb + base_conversion + IotaB13
        {
            let circuit = MyCircuit::<Fp> {
                in_state: in_state_fp,
                out_state: out_state_mix,
                next_mixing: Some(next_input_fp),
                is_mixing: true,
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
                in_state: out_state_non_mix,
                out_state: out_state_non_mix,
                next_mixing: Some(next_input_fp),
                is_mixing: true,
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
