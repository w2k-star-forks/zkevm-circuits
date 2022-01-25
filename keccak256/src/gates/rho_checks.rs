//! Inner checks in the Rho step
//!
//! ## Overview
//!
//! In the Rho checks we convert each lane from base 13 to base 9.
//! We call the base 13 lane the input and the base 9 lane the output.
//! We can view the lane as a polynomial
//! - where the input lane is `A(13) =  a0 13^0 + ... + a64 13^64`, and
//! - the output lane is  `B(9)  =  b0  9^0 + ... + b63  9^63`
//!
//! We call the a coefficient of the polynomial a chunk.
//!
//! The output chunks represent the output bits of the lane in binary, where b0
//! is the least significant bit and b63 is the most significant bit.
//!
//! Note that the input lane is special because it's an output from the Theta
//! step, so it has 65 chunks. It holds that `0 <= a0 + a64 < 13`. We refer a0
//! to be low value and a64 high value.
//!
//! In the Rho step we perform the **rotation** of chunk positions and the
//! **convertion** from base 13 to base 9.
//!
//! More formally speaking, we have a transform `T`, where `bi = T(aj)` for some
//! `i`, `j`, and `ai` is not special chunks.
//! For special chunk, `bi = T(a0 + a64)`.
//!
//! - The rotate means we perform the rotate left of the rotation specified in
//!   `ROTATION_CONSTANTS`. Say if our rotation is 3,
//! The a1 will be contribute to b3, and a63 will go to b0.
//!
//! The convert `T` is the [`crate::arith_helpers::convert_b13_coef`], in the
//! circuit we have to do a lookup check for that
//!
//! The lookup is more efficient when we lookup
//! multiple([`crate::gates::rho_helpers::BASE_NUM_OF_CHUNKS`]) chunks at a
//! time.
//!
//! ## Checks
//!
//! The goal is to check the conversion from the base 13 input lane to the base
//! 9 output lane is sound.
//!
//! ### The Essential
//!
//! For each lane, we split up the lane in slices of chunks.
//! - We run down the input accumulator by subtracting each `input_coef *
//!   power_of_13`
//! - We run up the output accumulator by adding up `output_coef * power_of_9`
//! - We lookup [`crate::gates::tables::Base13toBase9TableConfig`] and check the
//!   conversion between `input_coef` and `output_coef` is valid
//!
//! We have the copy constraint to glue input accumulator to input lane and the
//! output accumulator to output lane
//!
//! But we have special checks to do
//!
//! ### Sepcial Chunks
//!
//! The Theta step shifted left 1 chunk. So the base 13 input lane now has 65
//! chunks, where the 0th and the 64th input chunks contribute to the same
//! output chunk. We call the 0th input chunk the `low_value` and the 64th input
//! chunk the `high_value`. A the end of the running down input accumulator, the
//! remaining value is `low_value + high_value * 13**64` We lookup [`crate::
//! gates::tables::SpecialChunkTableConfig`] to convert it to
//! `convert_b13_coef(low_value + high_value)`.
//!
//! ### Overflow Checks
//!
//! The [`crate::gates::tables::Base13toBase9TableConfig`] table is built to
//! lookup 4 chunks. But we have chunks that are step 1, step 2, and step 3,
//! which means they suppose to have the last 1, 2, or 3 chunks to be 0.
//! If a step 1 step is witnessed with 2, 3, or 4 non-zero input chunks, then
//! it's a malicious overflow and we have to provent the prover from doing that.
//!
//! Doing range check for each of non-4chunks steps would be inefficient,
//! instead we use the following technique.
//!
//! We define the [`crate::gates::rho_helpers::OVERFLOW_TRANSFORM`] to map
//! `step` to a value `block_count`. We also add a column in
//! [`crate::gates::tables::Base13toBase9TableConfig`] to lookup `block_count`.
//! We sum up all the block_counts across 25 lanes, for each step 1, step 2, and
//! step 3. At the end of the Rho step we perform the final block count range
//! check in [`BlockCountFinalConfig`].
//!
//! The `OVERFLOW_TRANSFORM` maps step 1 to 0, step 2 to 1, step 3 to 13, and
//! step 4 to 170. It is defined that any possible overflow would result the
//! final block count check to fail.
//!
//! It would be better explained if we enumerate all the possible cases:
//!
//! The sum of the step 1 should be 0.
//! So that if prover witness any more than 1 non-zero chunks, the
//! [`crate::gates::tables::Base13toBase9TableConfig`] returns a block count 1,
//! 13, or 170 and fail the final sum check.
//!
//! The sum of the step 2 should be less than or equal to 1 times all numbers of
//! step 2, which can be counted at setup time to be 12. So that if prover
//! witness any more than 2 non-zero chunks, the
//! [`crate::gates::tables::Base13toBase9TableConfig`] returns a block count 13
//! or 170 and fail the final sum check.
//!
//! The sum of the step 3 should be less than or equal to 13 times all numbers
//! of step 3, which can be counted at setup time to be 13. So that if prover
//! witness any more than 3 non-zero chunks, the
//! [`crate::gates::tables::Base13toBase9TableConfig`] returns a block count 170
//! and fail the final sum check.
use crate::arith_helpers::*;
use crate::common::{LANE_SIZE, ROTATION_CONSTANTS};
use crate::gates::{
    gate_helpers::*,
    rho_helpers::*,
    tables::{Base13toBase9TableConfig, SpecialChunkTableConfig},
};
use halo2::{
    circuit::{Cell, Layouter, Region},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector,
    },
    poly::Rotation,
};
use pairing::arithmetic::FieldExt;
use std::iter;
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct LaneRotateConversionConfig<F> {
    rotation: u32,
    lane_idx: usize,
    q_normal: Selector,
    q_special: Selector,
    input_coef: Column<Advice>,
    input_pob: Column<Fixed>,
    input_acc: Column<Advice>,
    output_coef: Column<Advice>,
    output_pob: Column<Fixed>,
    output_acc: Column<Advice>,
    overflow_detector: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> LaneRotateConversionConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        lane_idx: usize,
        lane: Column<Advice>,
        base13_to_9_table: Base13toBase9TableConfig<F>,
        special_chunk_table: SpecialChunkTableConfig<F>,
    ) -> Self {
        meta.enable_equality(lane.into());
        let rotation = {
            let x = lane_idx % 5;
            let y = lane_idx / 5;
            ROTATION_CONSTANTS[x][y]
        };

        let q_normal = meta.complex_selector();
        let q_special = meta.complex_selector();
        let input_coef = meta.advice_column();
        let input_pob = meta.fixed_column();
        let input_acc = meta.advice_column();
        let output_coef = meta.advice_column();
        let output_pob = meta.fixed_column();
        let output_acc = meta.advice_column();
        let overflow_detector = meta.advice_column();

        meta.enable_equality(input_acc.into());
        meta.enable_equality(output_acc.into());
        meta.enable_equality(overflow_detector.into());

        // | coef | 13**x | acc       |
        // |------|-------|-----------|
        // |  a   |  b    | c         |
        // |  ... | ...   | c - a * b |
        meta.create_gate("Running down input", |meta| {
            let q_normal = meta.query_selector(q_normal);
            let coef = meta.query_advice(input_coef, Rotation::cur());
            let pob = meta.query_fixed(input_pob, Rotation::cur());
            let acc = meta.query_advice(input_acc, Rotation::cur());
            let acc_next = meta.query_advice(input_acc, Rotation::next());
            vec![(
                "delta_acc === - coef * power_of_base",
                q_normal * (acc_next - acc + coef * pob),
            )]
        });
        // | coef | 9**x  |    acc |
        // |------|-------|--------|
        // |  a   |  b    |      0 |
        // |  ... | ...   |  a * b |
        meta.create_gate("Running up for output", |meta| {
            let q_normal = meta.query_selector(q_normal);
            let q_special = meta.query_selector(q_special);
            let coef = meta.query_advice(output_coef, Rotation::cur());
            let pob = meta.query_fixed(output_pob, Rotation::cur());
            let acc = meta.query_advice(output_acc, Rotation::cur());
            let acc_next = meta.query_advice(output_acc, Rotation::next());
            // delta_acc === coef * power_of_base
            let poly = acc_next - acc.clone() - coef * pob;
            vec![
                ("check for q_normal", q_normal * poly.clone()),
                ("check for q_special", q_special * poly),
            ]
        });

        meta.lookup(|meta| {
            let q_normal = meta.query_selector(q_normal);
            let base13_coef = meta.query_advice(input_coef, Rotation::cur());
            let base9_coef = meta.query_advice(output_coef, Rotation::cur());
            let od = meta.query_advice(overflow_detector, Rotation::cur());

            vec![
                (q_normal.clone() * base13_coef, base13_to_9_table.base13),
                (q_normal.clone() * base9_coef, base13_to_9_table.base9),
                (q_normal * od, base13_to_9_table.block_count),
            ]
        });

        meta.lookup(|meta| {
            let q_special = meta.query_selector(q_special);
            let input_acc = meta.query_advice(input_acc, Rotation::cur());
            let output_coef = meta.query_advice(output_coef, Rotation::cur());

            vec![
                (
                    q_special.clone() * input_acc,
                    special_chunk_table.last_chunk,
                ),
                (q_special * output_coef, special_chunk_table.output_coef),
            ]
        });

        let step2_acc = SumConfig::configure(meta, overflow_detector);
        let step3_acc = SumConfig::configure(meta, overflow_detector);

        Self {
            rotation,
            lane_idx,
            q_normal,
            q_special,
            input_coef,
            input_pob,
            input_acc,
            output_coef,
            output_pob,
            output_acc,
            overflow_detector,
            _marker: PhantomData,
        }
    }
    pub fn assign_region(
        &self,
        layouter: &mut impl Layouter<F>,
        lane_base_13: (Cell, F),
    ) -> Result<((Cell, F), Vec<(Cell, F)>, Vec<(Cell, F)>), Error> {
        let (conversions, special) =
            RhoLane::new(f_to_biguint(lane_base_13.1), self.rotation)
                .get_full_witness();
        layouter.assign_region(
            || "lane rotate conversion",
            |mut region| {
                let slices = slice_lane(self.rotation);
                let (od_cells, step2_od, step3_od) = {
                    let mut od_cells = Vec::with_capacity(slices.len());
                    let mut step2_od: Vec<(Cell, F)> = vec![];
                    let mut step3_od: Vec<(Cell, F)> = vec![];
                    for (offset, ((chunk_idx, step), conv)) in
                        slices.iter().zip(conversions).enumerate()
                    {
                        self.q_normal.enable(&mut region, offset)?;
                        region.assign_advice(
                            || format!("Input Coef {}", chunk_idx),
                            self.input_coef,
                            offset,
                            || Ok(biguint_to_f::<F>(&conv.input.coef)),
                        )?;
                        region.assign_fixed(
                            || format!("Input power of base"),
                            self.input_pob,
                            offset,
                            || Ok(biguint_to_f::<F>(&conv.input.power_of_base)),
                        )?;
                        {
                            let cell = region.assign_advice(
                                || "Input accumulator",
                                self.input_acc,
                                offset,
                                || Ok(biguint_to_f::<F>(&conv.input.pre_acc)),
                            )?;
                            if offset == 0 {
                                region.constrain_equal(lane_base_13.0, cell)?;
                            }
                        }
                        region.assign_advice(
                            || "Output Coef",
                            self.output_coef,
                            offset,
                            || Ok(biguint_to_f::<F>(&conv.output.coef)),
                        )?;
                        region.assign_fixed(
                            || format!("Output power of base"),
                            self.output_pob,
                            offset,
                            || Ok(biguint_to_f::<F>(&conv.input.power_of_base)),
                        )?;
                        {
                            let cell = region.assign_advice(
                                || "Output accumulator",
                                self.output_acc,
                                offset,
                                || Ok(biguint_to_f::<F>(&conv.output.pre_acc)),
                            )?;
                            if offset == 0 {
                                region.constrain_constant(cell, F::zero())?;
                            }
                        }
                        let od = {
                            let value = F::from(
                                conv.overflow_detector.block_count.into(),
                            );
                            let cell = region.assign_advice(
                                || "Overflow detector",
                                self.overflow_detector,
                                offset,
                                || Ok(value),
                            )?;
                            (cell, value)
                        };
                        match step {
                            2 => step2_od.push(od),
                            3 => step3_od.push(od),
                            _ => {}
                        }
                        od_cells.push(od);
                    }
                    (od_cells, step2_od, step3_od)
                };
                // special chunks
                let output_lane = {
                    let offset = slices.len();
                    self.q_special.enable(&mut region, offset)?;
                    region.assign_advice(
                        || format!("Special Input acc",),
                        self.input_acc,
                        offset,
                        || Ok(biguint_to_f::<F>(&special.input)),
                    )?;
                    region.assign_advice(
                        || format!("Special output coef",),
                        self.output_coef,
                        offset,
                        || Ok(F::from(special.output_coef.into())),
                    )?;
                    region.assign_fixed(
                        || format!("Special output power of base"),
                        self.output_pob,
                        offset,
                        || {
                            Ok(F::from(B9.into()).pow(&[
                                self.rotation.into(),
                                0,
                                0,
                                0,
                            ]))
                        },
                    )?;
                    region.assign_advice(
                        || format!("Special output acc pre",),
                        self.output_coef,
                        offset,
                        || Ok(biguint_to_f::<F>(&special.output_acc_pre)),
                    )?;
                    let lane = {
                        let value = biguint_to_f::<F>(&special.output_acc_post);
                        let cell = region.assign_advice(
                            || format!("Special output acc post",),
                            self.output_coef,
                            offset + 1,
                            || Ok(value),
                        )?;
                        (cell, value)
                    };
                    lane
                };
                Ok((output_lane, step2_od, step3_od))
            },
        )
    }
}

#[derive(Debug, Clone)]
pub struct SumConfig<F> {
    q_enable: Selector,
    x: Column<Advice>,
    sum: Column<Advice>,
    _marker: PhantomData<F>,
}
impl<F: FieldExt> SumConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        x: Column<Advice>,
    ) -> Self {
        meta.enable_equality(x.into());
        let q_enable = meta.selector();
        let sum = meta.advice_column();

        meta.enable_equality(sum.into());

        meta.create_gate("sum", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let x = meta.query_advice(x, Rotation::cur());
            let sum_next = meta.query_advice(sum, Rotation::next());
            let sum = meta.query_advice(sum, Rotation::cur());
            vec![q_enable * (sum_next - sum - x)]
        });
        Self {
            q_enable,
            x,
            sum,
            _marker: PhantomData,
        }
    }
    pub fn assign_region(
        &self,
        layouter: &mut impl Layouter<F>,
        xs: Vec<(Cell, F)>,
    ) -> Result<(Cell, F), Error> {
        debug_assert!(xs.len() > 1);
        layouter.assign_region(
            || "running sum",
            |mut region| {
                let sum = F::zero();
                let mut offset = 0;
                for &(cell_from, value) in xs.iter() {
                    let cell_to = region.assign_advice(
                        || "x",
                        self.x,
                        offset,
                        || Ok(value),
                    )?;
                    region.constrain_equal(cell_to, cell_from)?;
                    region.assign_advice(
                        || "sum",
                        self.sum,
                        offset,
                        || Ok(sum),
                    )?;
                    sum += value;
                    offset += 1;
                }
                let sum = {
                    let cell = region.assign_advice(
                        || "last sum",
                        self.sum,
                        offset,
                        || Ok(sum),
                    )?;
                    (cell, sum)
                };

                Ok(sum)
            },
        )
    }
}

/// Gates to check if block counts are accumulated correctly
#[derive(Debug, Clone)]
pub struct BlockCountAccConfig<F> {
    bc: BlockCountAdvices,
    step: u32,
    q_first: Selector,
    q_rest: Selector,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BlockCountAccConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_all: Selector,
        bc: BlockCountAdvices,
        step: u32,
    ) -> Self {
        let q_first = meta.complex_selector();
        let q_rest = meta.complex_selector();
        if step == 1 {
            meta.create_gate("block count step 1", |meta| {
                let q_all = meta.query_selector(q_all);
                let block_count =
                    meta.query_advice(bc.block_count, Rotation::cur());
                vec![("block_count === 0", q_all * block_count)]
            });
        }
        meta.create_gate("first row", |meta| {
            let q_first = meta.query_selector(q_first);
            let block_count =
                meta.query_advice(bc.block_count, Rotation::cur());
            let step2_acc = meta.query_advice(bc.step2_acc, Rotation::cur());
            let step3_acc = meta.query_advice(bc.step3_acc, Rotation::cur());
            vec![match step {
                2 => (
                    "first step2_acc === block_count",
                    q_first * (step2_acc - block_count),
                ),
                3 => (
                    "first step3_acc === block_count",
                    q_first * (step3_acc - block_count),
                ),
                1 | 4 => ("1 or 4", Expression::Constant(F::zero())),
                _ => unreachable!(),
            }]
        });

        meta.create_gate("Running up block count", |meta| {
            let q_rest = meta.query_selector(q_rest);
            let block_count =
                meta.query_advice(bc.block_count, Rotation::cur());
            let step2_acc = meta.query_advice(bc.step2_acc, Rotation::cur());
            let step2_acc_prev =
                meta.query_advice(bc.step2_acc, Rotation::prev());
            let step3_acc = meta.query_advice(bc.step3_acc, Rotation::cur());
            let step3_acc_prev =
                meta.query_advice(bc.step3_acc, Rotation::prev());

            let step2_poly = {
                if step == 2 {
                    (
                        "delta_step2 === block_count",
                        step2_acc - step2_acc_prev - block_count.clone(),
                    )
                } else {
                    ("delta_step2 === 0", step2_acc - step2_acc_prev)
                }
            };
            let step3_poly = {
                if step == 3 {
                    (
                        "delta_step3 === block_count",
                        step3_acc - step3_acc_prev - block_count,
                    )
                } else {
                    ("delta_step3 === 0", step3_acc - step3_acc_prev)
                }
            };

            vec![step2_poly, step3_poly]
                .iter()
                .map(|(name, poly)| (*name, q_rest.clone() * poly.clone()))
                .collect::<Vec<_>>()
        });

        Self {
            bc,
            step,
            q_first,
            q_rest,
            _marker: PhantomData,
        }
    }

    pub fn assign_region(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        ofdet: &OverflowDetector,
    ) -> Result<BlockCount2<F>, Error> {
        if offset == 0 {
            self.q_first.enable(region, 0)?;
        } else {
            self.q_rest.enable(region, offset)?;
        }
        region.assign_advice(
            || format!("block count step{}", self.step),
            self.bc.block_count,
            offset,
            || Ok(F::from(ofdet.block_count.into())),
        )?;
        let step2 = {
            let value = F::from(ofdet.step2_acc.into());
            let cell = region.assign_advice(
                || "step 2 bc acc",
                self.bc.step2_acc,
                offset,
                || Ok(value),
            )?;
            BlockCount { cell, value }
        };
        let step3 = {
            let value = F::from(ofdet.step3_acc.into());
            let cell = region.assign_advice(
                || "step 3 bc acc",
                self.bc.step3_acc,
                offset,
                || Ok(value),
            )?;
            BlockCount { cell, value }
        };
        Ok((step2, step3))
    }
}

#[derive(Debug, Clone)]
pub struct BlockCountFinalConfig<F> {
    q_enable: Selector,
    block_count_cols: [Column<Advice>; 2],
    _marker: PhantomData<F>,
}
impl<F: FieldExt> BlockCountFinalConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        block_count_cols: [Column<Advice>; 2],
    ) -> Self {
        let q_enable = meta.complex_selector();
        for column in block_count_cols.iter() {
            meta.enable_equality((*column).into());
        }

        meta.create_gate("block count final check", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let step2_acc =
                meta.query_advice(block_count_cols[0], Rotation::cur());
            let step3_acc =
                meta.query_advice(block_count_cols[1], Rotation::cur());
            let one = Expression::Constant(F::one());
            iter::empty()
                .chain(Some((
                    "step2_acc <= 12",
                    (0..=STEP2_RANGE)
                        .map(|x| {
                            step2_acc.clone() - Expression::Constant(F::from(x))
                        })
                        .fold(one.clone(), |acc, x| acc * x),
                )))
                .chain(Some((
                    "step3_acc <= 13 * 13",
                    (0..=STEP3_RANGE)
                        .map(|x| {
                            step3_acc.clone() - Expression::Constant(F::from(x))
                        })
                        .fold(one, |acc, x| acc * x),
                )))
                .map(|(name, poly)| (name, q_enable.clone() * poly))
                .collect::<Vec<_>>()
        });

        Self {
            q_enable,
            block_count_cols,
            _marker: PhantomData,
        }
    }
    pub fn assign_region(
        &self,
        layouter: &mut impl Layouter<F>,
        block_count_cells: [BlockCount2<F>; 25],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "final block count",
            |mut region| {
                for (offset, bc) in block_count_cells.iter().enumerate() {
                    self.q_enable.enable(&mut region, offset)?;
                    let cell_1 = region.assign_advice(
                        || format!("block_count step2 acc lane {}", offset),
                        self.block_count_cols[0],
                        offset,
                        || Ok(bc.0.value),
                    )?;
                    region.constrain_equal(cell_1, bc.0.cell)?;
                    let cell_2 = region.assign_advice(
                        || format!("block_count step3 acc lane {}", offset),
                        self.block_count_cols[1],
                        offset,
                        || Ok(bc.1.value),
                    )?;
                    region.constrain_equal(cell_2, bc.1.cell)?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}
