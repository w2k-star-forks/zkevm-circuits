use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_ACCOUNT_ADDRESS,
        step::ExecutionState,
        table::CallContextFieldTag,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition::Delta,
            },
            from_bytes, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::eth_types::ToLittleEndian;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub(crate) struct CallerGadget<F> {
    same_context: SameContextGadget<F>,
    // Using RLC to match against rw_table->stack_op value
    caller_address: RandomLinearCombination<F, 20>,
}

impl<F: FieldExt> ExecutionGadget<F> for CallerGadget<F> {
    const NAME: &'static str = "CALLER";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLER;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let caller_address = cb.query_rlc::<N_BYTES_ACCOUNT_ADDRESS>();

        // Lookup rw_table -> call_context with caller address
        cb.call_context_lookup(
            false.expr(),
            None, // cb.curr.state.call_id
            CallContextFieldTag::CallerAddress,
            from_bytes::expr(&caller_address.cells),
        );

        // Push the value to the stack
        cb.stack_push(caller_address.expr());

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
            caller_address,
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

        let caller = block.rws[step.rw_indices[1]].stack_value();

        self.caller_address.assign(
            region,
            offset,
            Some(caller.to_le_bytes()[..20].try_into().unwrap()),
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
            CALLER
            STOP
        };
        let block = witness::build_block_from_trace_code_at_start(&bytecode);
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }
    #[test]
    fn caller_gadget_test() {
        test_ok();
    }
}
