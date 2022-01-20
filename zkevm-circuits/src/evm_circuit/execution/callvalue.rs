use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::CallContextFieldTag,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition::Delta,
            },
            Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::eth_types::ToLittleEndian;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct CallValueGadget<F> {
    same_context: SameContextGadget<F>,
    // Value in rw_table->stack_op and call_context->call_value are both RLC
    // encoded, so no need to decode.
    call_value: Cell<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for CallValueGadget<F> {
    const NAME: &'static str = "CALLVALUE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLVALUE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let call_value = cb.query_cell();

        // Lookup rw_table -> call_context with call value
        cb.call_context_lookup(
            false.expr(),
            None, // cb.curr.state.call_id
            CallContextFieldTag::Value,
            call_value.expr(),
        );

        // Push the value to the stack
        cb.stack_push(call_value.expr());

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(
            cb,
            opcode,
            step_state_transition,
            None,
        );

        Self {
            same_context,
            call_value,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let call_value = block.rws[step.rw_indices[1]].stack_value();

        self.call_value.assign(
            region,
            offset,
            Some(Word::random_linear_combine(
                call_value.to_le_bytes(),
                block.randomness,
            )),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        test::run_test_circuit_incomplete_fixed_table, witness,
    };
    use bus_mapping::bytecode;

    fn test_ok() {
        let bytecode = bytecode! {
            #[start]
            CALLVALUE
            STOP
        };
        let block = witness::build_block_from_trace_code_at_start(&bytecode);
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }
    #[test]
    fn callvalue_gadget_test() {
        test_ok();
    }
}
