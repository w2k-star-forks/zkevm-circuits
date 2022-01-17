#![allow(missing_docs)]
use crate::evm_circuit::{
    param::STACK_CAPACITY,
    step::ExecutionState,
    table::{
        AccountFieldTag, BlockContextFieldTag, CallContextFieldTag, RwTableTag,
        TxContextFieldTag,
    },
    util::RandomLinearCombination,
};
use bus_mapping::{
    circuit_input_builder::CircuitInputBuilder,
    eth_types::{Address, ToLittleEndian, ToScalar, ToWord, Word},
    evm::OpcodeId,
    external_tracer,
    operation::{self, AccountField, CallContextField},
    state_db,
};
use halo2::arithmetic::{BaseExt, FieldExt};
use pairing::bn256::Fr as Fp;
use sha3::{Digest, Keccak256};
use std::{collections::HashMap, convert::TryInto};

#[derive(Debug, Default)]
pub struct Block<F> {
    // randomness for random linear combination
    pub randomness: F,
    pub txs: Vec<Transaction>,
    pub rws: RwMap,
    pub bytecodes: Vec<Bytecode>,
    pub context: BlockContext,
}

#[derive(Debug, Default)]
pub struct BlockContext {
    pub coinbase: Address,
    pub gas_limit: u64,
    pub number: Word,
    pub timestamp: Word,
    pub difficulty: Word,
    pub base_fee: Word,
    pub history_hashes: Vec<Word>,
}

impl BlockContext {
    pub fn table_assignments<F: FieldExt>(&self, randomness: F) -> Vec<[F; 3]> {
        [
            vec![
                [
                    F::from(BlockContextFieldTag::Coinbase as u64),
                    F::zero(),
                    self.coinbase.to_scalar().unwrap(),
                ],
                [
                    F::from(BlockContextFieldTag::GasLimit as u64),
                    F::zero(),
                    F::from(self.gas_limit),
                ],
                [
                    F::from(BlockContextFieldTag::Number as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.number.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from(BlockContextFieldTag::Timestamp as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.timestamp.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from(BlockContextFieldTag::Difficulty as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.difficulty.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from(BlockContextFieldTag::BaseFee as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.base_fee.to_le_bytes(),
                        randomness,
                    ),
                ],
            ],
            self.history_hashes
                .iter()
                .enumerate()
                .map(|(idx, hash)| {
                    [
                        F::from(BlockContextFieldTag::BlockHash as u64),
                        (self.number - idx - 1).to_scalar().unwrap(),
                        RandomLinearCombination::random_linear_combine(
                            hash.to_le_bytes(),
                            randomness,
                        ),
                    ]
                })
                .collect(),
        ]
        .concat()
    }
}

#[derive(Debug, Default)]
pub struct Transaction {
    pub id: usize,
    pub nonce: u64,
    pub gas: u64,
    pub gas_price: Word,
    pub caller_address: Address,
    pub callee_address: Address,
    pub is_create: bool,
    pub value: Word,
    pub call_data: Vec<u8>,
    pub call_data_length: usize,
    pub call_data_gas_cost: u64,
    pub calls: Vec<Call>,
    pub steps: Vec<ExecStep>,
}

impl Transaction {
    pub fn table_assignments<F: FieldExt>(&self, randomness: F) -> Vec<[F; 4]> {
        [
            vec![
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::Nonce as u64),
                    F::zero(),
                    F::from(self.nonce),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::Gas as u64),
                    F::zero(),
                    F::from(self.gas),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::GasPrice as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.gas_price.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::CallerAddress as u64),
                    F::zero(),
                    self.caller_address.to_scalar().unwrap(),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::CalleeAddress as u64),
                    F::zero(),
                    self.callee_address.to_scalar().unwrap(),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::IsCreate as u64),
                    F::zero(),
                    F::from(self.is_create as u64),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::Value as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.value.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::CallDataLength as u64),
                    F::zero(),
                    F::from(self.call_data_length as u64),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::CallDataGasCost as u64),
                    F::zero(),
                    F::from(self.call_data_gas_cost),
                ],
            ],
            self.call_data
                .iter()
                .enumerate()
                .map(|(idx, byte)| {
                    [
                        F::from(self.id as u64),
                        F::from(TxContextFieldTag::CallData as u64),
                        F::from(idx as u64),
                        F::from(*byte as u64),
                    ]
                })
                .collect(),
        ]
        .concat()
    }
}

#[derive(Debug)]
pub enum CodeSource {
    Account(Word),
}

impl Default for CodeSource {
    fn default() -> Self {
        Self::Account(0.into())
    }
}

#[derive(Debug, Default)]
pub struct Call {
    pub id: usize,
    pub is_root: bool,
    pub is_create: bool,
    pub code_source: CodeSource,
    pub rw_counter_end_of_reversion: usize,
    pub caller_call_id: usize,
    pub depth: usize,
    pub caller_address: Address,
    pub callee_address: Address,
    pub call_data_offset: u64,
    pub call_data_length: u64,
    pub return_data_offset: u64,
    pub return_data_length: u64,
    pub value: Word,
    pub is_success: bool,
    pub is_persistent: bool,
    pub is_static: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ExecStep {
    pub call_idx: usize,
    pub rw_indices: Vec<(RwTableTag, usize)>,
    pub execution_state: ExecutionState,
    pub rw_counter: usize,
    pub program_counter: u64,
    pub stack_pointer: usize,
    pub gas_left: u64,
    pub gas_cost: u64,
    pub memory_size: u32,
    pub state_write_counter: usize,
    pub opcode: Option<OpcodeId>,
}

#[derive(Debug)]
pub struct Bytecode {
    pub hash: Word,
    pub bytes: Vec<u8>,
}

impl Bytecode {
    pub fn new(bytes: Vec<u8>) -> Self {
        let hash = Word::from_big_endian(Keccak256::digest(&bytes).as_slice());
        Self { hash, bytes }
    }

    pub fn table_assignments<'a, F: FieldExt>(
        &'a self,
        randomness: F,
    ) -> impl Iterator<Item = [F; 4]> + '_ {
        struct BytecodeIterator<'a, F> {
            idx: usize,
            push_data_left: usize,
            hash: F,
            bytes: &'a [u8],
        }

        impl<'a, F: FieldExt> Iterator for BytecodeIterator<'a, F> {
            type Item = [F; 4];

            fn next(&mut self) -> Option<Self::Item> {
                if self.idx == self.bytes.len() {
                    return None;
                }

                let idx = self.idx;
                let byte = self.bytes[self.idx];
                let mut is_code = true;

                if self.push_data_left > 0 {
                    is_code = false;
                    self.push_data_left -= 1;
                } else if (OpcodeId::PUSH1.as_u8()..=OpcodeId::PUSH32.as_u8())
                    .contains(&byte)
                {
                    self.push_data_left =
                        byte as usize - (OpcodeId::PUSH1.as_u8() - 1) as usize;
                }

                self.idx += 1;

                Some([
                    self.hash,
                    F::from(idx as u64),
                    F::from(byte as u64),
                    F::from(is_code as u64),
                ])
            }
        }

        BytecodeIterator {
            idx: 0,
            push_data_left: 0,
            hash: RandomLinearCombination::random_linear_combine(
                self.hash.to_le_bytes(),
                randomness,
            ),
            bytes: &self.bytes,
        }
    }
}

#[derive(Debug, Default)]
pub struct RwMap(pub HashMap<RwTableTag, Vec<Rw>>);

impl std::ops::Index<(RwTableTag, usize)> for RwMap {
    type Output = Rw;

    fn index(&self, (tag, idx): (RwTableTag, usize)) -> &Self::Output {
        &self.0.get(&tag).unwrap()[idx]
    }
}

#[derive(Clone, Debug)]
pub enum Rw {
    TxAccessListAccount {
        rw_counter: usize,
        is_write: bool,
        tx_id: usize,
        account_address: Address,
        value: bool,
        value_prev: bool,
    },
    TxAccessListAccountStorage {
        rw_counter: usize,
        is_write: bool,
        tx_id: usize,
        account_address: Address,
        storage_key: Word,
        value: bool,
        value_prev: bool,
    },
    TxRefund {
        rw_counter: usize,
        is_write: bool,
    },
    Account {
        rw_counter: usize,
        is_write: bool,
        account_address: Address,
        field_tag: AccountFieldTag,
        value: Word,
        value_prev: Word,
    },
    AccountStorage {
        rw_counter: usize,
        is_write: bool,
        account_address: Address,
        storage_key: Word,
        value: Word,
        value_prev: Word,
    },
    CallContext {
        rw_counter: usize,
        is_write: bool,
        call_id: usize,
        field_tag: CallContextFieldTag,
        value: Word,
    },
    Stack {
        rw_counter: usize,
        is_write: bool,
        call_id: usize,
        stack_pointer: usize,
        value: Word,
    },
    Memory {
        rw_counter: usize,
        is_write: bool,
        call_id: usize,
        memory_address: u64,
        byte: u8,
    },
}

impl Rw {
    pub fn tx_access_list_value_pair(&self) -> (bool, bool) {
        match self {
            Self::TxAccessListAccount {
                value, value_prev, ..
            } => (*value, *value_prev),
            Self::TxAccessListAccountStorage {
                value, value_prev, ..
            } => (*value, *value_prev),
            _ => unreachable!(),
        }
    }

    pub fn account_value_pair(&self) -> (Word, Word) {
        match self {
            Self::Account {
                value, value_prev, ..
            } => (*value, *value_prev),
            _ => unreachable!(),
        }
    }

    pub fn call_context_value(&self) -> Word {
        match self {
            Self::CallContext { value, .. } => *value,
            _ => unreachable!(),
        }
    }

    pub fn stack_value(&self) -> Word {
        match self {
            Self::Stack { value, .. } => *value,
            _ => unreachable!(),
        }
    }

    pub fn table_assignment<F: FieldExt>(&self, randomness: F) -> [F; 8] {
        match self {
            Self::TxAccessListAccount {
                rw_counter,
                is_write,
                tx_id,
                account_address,
                value,
                value_prev,
            } => [
                F::from(*rw_counter as u64),
                F::from(*is_write as u64),
                F::from(RwTableTag::TxAccessListAccount as u64),
                F::from(*tx_id as u64),
                account_address.to_scalar().unwrap(),
                F::from(*value as u64),
                F::from(*value_prev as u64),
                F::zero(),
            ],
            Self::TxAccessListAccountStorage {
                rw_counter,
                is_write,
                tx_id,
                account_address,
                storage_key,
                value,
                value_prev,
            } => [
                F::from(*rw_counter as u64),
                F::from(*is_write as u64),
                F::from(RwTableTag::TxAccessListAccount as u64),
                F::from(*tx_id as u64),
                account_address.to_scalar().unwrap(),
                RandomLinearCombination::random_linear_combine(
                    storage_key.to_le_bytes(),
                    randomness,
                ),
                F::from(*value as u64),
                F::from(*value_prev as u64),
            ],
            Self::Account {
                rw_counter,
                is_write,
                account_address,
                field_tag,
                value,
                value_prev,
            } => {
                let to_scalar = |value: &Word| match field_tag {
                    AccountFieldTag::Nonce => value.to_scalar().unwrap(),
                    _ => RandomLinearCombination::random_linear_combine(
                        value.to_le_bytes(),
                        randomness,
                    ),
                };
                [
                    F::from(*rw_counter as u64),
                    F::from(*is_write as u64),
                    F::from(RwTableTag::Account as u64),
                    account_address.to_scalar().unwrap(),
                    F::from(*field_tag as u64),
                    to_scalar(value),
                    to_scalar(value_prev),
                    F::zero(),
                ]
            }
            Self::CallContext {
                rw_counter,
                is_write,
                call_id,
                field_tag,
                value,
            } => [
                F::from(*rw_counter as u64),
                F::from(*is_write as u64),
                F::from(RwTableTag::CallContext as u64),
                F::from(*call_id as u64),
                F::from(*field_tag as u64),
                match field_tag {
                    CallContextFieldTag::CodeSource
                    | CallContextFieldTag::Value => {
                        RandomLinearCombination::random_linear_combine(
                            value.to_le_bytes(),
                            randomness,
                        )
                    }
                    CallContextFieldTag::CallerAddress
                    | CallContextFieldTag::CalleeAddress
                    | CallContextFieldTag::IsSuccess => {
                        value.to_scalar().unwrap()
                    }
                    _ => F::from(value.low_u64()),
                },
                F::zero(),
                F::zero(),
            ],
            Self::Stack {
                rw_counter,
                is_write,
                call_id,
                stack_pointer,
                value,
            } => [
                F::from(*rw_counter as u64),
                F::from(*is_write as u64),
                F::from(RwTableTag::Stack as u64),
                F::from(*call_id as u64),
                F::from(*stack_pointer as u64),
                RandomLinearCombination::random_linear_combine(
                    value.to_le_bytes(),
                    randomness,
                ),
                F::zero(),
                F::zero(),
            ],
            Self::Memory {
                rw_counter,
                is_write,
                call_id,
                memory_address,
                byte,
            } => [
                F::from(*rw_counter as u64),
                F::from(*is_write as u64),
                F::from(RwTableTag::Memory as u64),
                F::from(*call_id as u64),
                F::from(*memory_address),
                F::from(*byte as u64),
                F::zero(),
                F::zero(),
            ],
            _ => unimplemented!(),
        }
    }
}

impl From<&operation::OperationContainer> for RwMap {
    fn from(container: &operation::OperationContainer) -> Self {
        let mut rws = HashMap::default();

        // TODO:
        rws.insert(RwTableTag::TxAccessListAccountStorage, vec![]);
        rws.insert(RwTableTag::TxRefund, vec![]);
        rws.insert(RwTableTag::AccountStorage, vec![]);
        rws.insert(RwTableTag::AccountDestructed, vec![]);

        rws.insert(
            RwTableTag::TxAccessListAccount,
            container
                .tx_access_list_account
                .iter()
                .map(|op| Rw::TxAccessListAccount {
                    rw_counter: op.rwc().into(),
                    is_write: true,
                    tx_id: op.op().tx_id,
                    account_address: op.op().address,
                    value: op.op().value,
                    value_prev: op.op().value_prev,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::Account,
            container
                .account
                .iter()
                .map(|op| Rw::Account {
                    rw_counter: op.rwc().into(),
                    is_write: op.op().rw.is_write(),
                    account_address: op.op().address,
                    field_tag: match op.op().field {
                        AccountField::Nonce => AccountFieldTag::Nonce,
                        AccountField::Balance => AccountFieldTag::Balance,
                        AccountField::CodeHash => AccountFieldTag::CodeHash,
                    },
                    value: op.op().value,
                    value_prev: op.op().value_prev,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::CallContext,
            container
                .call_context
                .iter()
                .map(|op| Rw::CallContext {
                    rw_counter: op.rwc().into(),
                    is_write: op.op().rw.is_write(),
                    call_id: op.op().call_id,
                    field_tag: match op.op().field {
                        CallContextField::RwCounterEndOfReversion => {
                            CallContextFieldTag::RwCounterEndOfReversion
                        }
                        CallContextField::CallerId => {
                            CallContextFieldTag::CallerId
                        }
                        CallContextField::TxId => CallContextFieldTag::TxId,
                        CallContextField::Depth => CallContextFieldTag::Depth,
                        CallContextField::CallerAddress => {
                            CallContextFieldTag::CallerAddress
                        }
                        CallContextField::CalleeAddress => {
                            CallContextFieldTag::CalleeAddress
                        }
                        CallContextField::CallDataOffset => {
                            CallContextFieldTag::CallDataOffset
                        }
                        CallContextField::CallDataLength => {
                            CallContextFieldTag::CallDataLength
                        }
                        CallContextField::ReturnDataOffset => {
                            CallContextFieldTag::ReturnDataOffset
                        }
                        CallContextField::ReturnDataLength => {
                            CallContextFieldTag::ReturnDataLength
                        }
                        CallContextField::Value => CallContextFieldTag::Value,
                        CallContextField::IsSuccess => {
                            CallContextFieldTag::IsSuccess
                        }
                        CallContextField::IsPersistent => {
                            CallContextFieldTag::IsPersistent
                        }
                        CallContextField::IsStatic => {
                            CallContextFieldTag::IsStatic
                        }
                        CallContextField::LastCalleeId => {
                            CallContextFieldTag::LastCalleeId
                        }
                        CallContextField::LastCalleeReturnDataOffset => {
                            CallContextFieldTag::LastCalleeReturnDataOffset
                        }
                        CallContextField::LastCalleeReturnDataLength => {
                            CallContextFieldTag::LastCalleeReturnDataLength
                        }
                        CallContextField::IsRoot => CallContextFieldTag::IsRoot,
                        CallContextField::IsCreate => {
                            CallContextFieldTag::IsCreate
                        }
                        CallContextField::CodeSource => {
                            CallContextFieldTag::CodeSource
                        }
                        CallContextField::ProgramCounter => {
                            CallContextFieldTag::ProgramCounter
                        }
                        CallContextField::StackPointer => {
                            CallContextFieldTag::StackPointer
                        }
                        CallContextField::GasLeft => {
                            CallContextFieldTag::GasLeft
                        }
                        CallContextField::MemorySize => {
                            CallContextFieldTag::MemorySize
                        }
                        CallContextField::StateWriteCounter => {
                            CallContextFieldTag::StateWriteCounter
                        }
                    },
                    value: op.op().value,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::Stack,
            container
                .stack
                .iter()
                .map(|op| Rw::Stack {
                    rw_counter: op.rwc().into(),
                    is_write: op.op().rw().is_write(),
                    call_id: op.op().call_id(),
                    stack_pointer: usize::from(*op.op().address()),
                    value: *op.op().value(),
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::Memory,
            container
                .memory
                .iter()
                .map(|op| Rw::Memory {
                    rw_counter: op.rwc().into(),
                    is_write: op.op().rw().is_write(),
                    call_id: op.op().call_id(),
                    memory_address: u64::from_le_bytes(
                        op.op().address().to_le_bytes()[..8]
                            .try_into()
                            .unwrap(),
                    ),
                    byte: op.op().value(),
                })
                .collect(),
        );

        Self(rws)
    }
}

impl From<&bus_mapping::circuit_input_builder::ExecStep> for ExecutionState {
    fn from(step: &bus_mapping::circuit_input_builder::ExecStep) -> Self {
        // TODO: error reporting. (errors are defined in
        // circuit_input_builder.rs)
        assert!(step.error.is_none());
        if step.op.is_dup() {
            return ExecutionState::DUP;
        }
        if step.op.is_push() {
            return ExecutionState::PUSH;
        }
        if step.op.is_swap() {
            return ExecutionState::SWAP;
        }
        match step.op {
            OpcodeId::ADD => ExecutionState::ADD,
            OpcodeId::MUL => ExecutionState::MUL,
            OpcodeId::SUB => ExecutionState::ADD,
            OpcodeId::EQ => ExecutionState::CMP,
            OpcodeId::GT => ExecutionState::CMP,
            OpcodeId::LT => ExecutionState::CMP,
            OpcodeId::SIGNEXTEND => ExecutionState::SIGNEXTEND,
            // TODO: Convert REVERT and RETURN to their own ExecutionState.
            OpcodeId::STOP | OpcodeId::REVERT | OpcodeId::RETURN => {
                ExecutionState::STOP
            }
            OpcodeId::AND => ExecutionState::BITWISE,
            OpcodeId::XOR => ExecutionState::BITWISE,
            OpcodeId::OR => ExecutionState::BITWISE,
            OpcodeId::POP => ExecutionState::POP,
            OpcodeId::PUSH32 => ExecutionState::PUSH,
            OpcodeId::BYTE => ExecutionState::BYTE,
            OpcodeId::MLOAD => ExecutionState::MEMORY,
            OpcodeId::MSTORE => ExecutionState::MEMORY,
            OpcodeId::MSTORE8 => ExecutionState::MEMORY,
            OpcodeId::JUMPDEST => ExecutionState::JUMPDEST,
            OpcodeId::JUMP => ExecutionState::JUMP,
            OpcodeId::JUMPI => ExecutionState::JUMPI,
            OpcodeId::PC => ExecutionState::PC,
            OpcodeId::MSIZE => ExecutionState::MSIZE,
            OpcodeId::CALLER => ExecutionState::CALLER,
            OpcodeId::CALLVALUE => ExecutionState::CALLVALUE,
            OpcodeId::COINBASE => ExecutionState::COINBASE,
            OpcodeId::CALL => ExecutionState::CALL,
            _ => unimplemented!("unimplemented opcode {:?}", step.op),
        }
    }
}

impl From<&bus_mapping::bytecode::Bytecode> for Bytecode {
    fn from(b: &bus_mapping::bytecode::Bytecode) -> Self {
        Bytecode::new(b.to_vec())
    }
}

fn step_convert(
    step: &bus_mapping::circuit_input_builder::ExecStep,
) -> ExecStep {
    let result = ExecStep {
        call_idx: step.call_index,
        rw_indices: step
            .bus_mapping_instance
            .iter()
            .map(|x| {
                let tag = match x.target() {
                    operation::Target::Memory => RwTableTag::Memory,
                    operation::Target::Stack => RwTableTag::Stack,
                    operation::Target::Storage => RwTableTag::AccountStorage,
                    operation::Target::TxAccessListAccount => {
                        RwTableTag::TxAccessListAccount
                    }
                    operation::Target::TxAccessListAccountStorage => {
                        RwTableTag::TxAccessListAccountStorage
                    }
                    operation::Target::TxRefund => RwTableTag::TxRefund,
                    operation::Target::Account => RwTableTag::Account,
                    operation::Target::AccountDestructed => {
                        RwTableTag::AccountDestructed
                    }
                    operation::Target::CallContext => RwTableTag::CallContext,
                };
                (tag, x.as_usize())
            })
            .collect(),
        execution_state: ExecutionState::from(step),
        rw_counter: usize::from(step.rwc),
        program_counter: usize::from(step.pc) as u64,
        stack_pointer: STACK_CAPACITY - step.stack_size,
        gas_left: step.gas_left.0,
        gas_cost: step.gas_cost.as_u64(),
        opcode: Some(step.op),
        // Memory size in word
        memory_size: (step.memory_size as u64 / 32) as u32,
        state_write_counter: step.swc,
    };
    result
}

fn tx_convert(
    tx: &bus_mapping::circuit_input_builder::Transaction,
) -> Transaction {
    Transaction {
        id: 1,
        nonce: tx.nonce,
        gas: tx.gas,
        gas_price: tx.gas_price,
        caller_address: tx.from,
        callee_address: tx.to,
        is_create: tx.is_create(),
        value: tx.value,
        call_data: tx.input.clone(),
        call_data_length: tx.input.len(),
        call_data_gas_cost: tx
            .input
            .iter()
            .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 }),
        calls: tx
            .calls()
            .iter()
            .map(|call| Call {
                id: call.call_id,
                is_root: call.is_root,
                is_create: call.is_create(),
                code_source: match call.code_source {
                    bus_mapping::circuit_input_builder::CodeSource::Address(
                        _,
                    ) => CodeSource::Account(call.code_hash.to_word()),
                    _ => unimplemented!(),
                },
                rw_counter_end_of_reversion: call.rw_counter_end_of_reversion,
                caller_call_id: 0,
                depth: call.depth,
                caller_address: call.caller_address,
                callee_address: call.address,
                call_data_offset: call.call_data_offset,
                call_data_length: call.call_data_length,
                return_data_offset: call.return_data_offset,
                return_data_length: call.return_data_length,
                value: call.value,
                is_success: call.is_success,
                is_persistent: call.is_persistent,
                is_static: call.is_static,
            })
            .collect(),
        steps: tx.steps().iter().map(step_convert).collect(),
    }
}

pub fn block_convert(
    block: &bus_mapping::circuit_input_builder::Block,
    code_db: &bus_mapping::state_db::CodeDB,
) -> Block<Fp> {
    Block {
        randomness: Fp::rand(),
        context: BlockContext {
            coinbase: block.block_const.coinbase,
            gas_limit: block.block_const.gas_limit.low_u64(),
            number: block.block_const.number.low_u64().into(),
            timestamp: block.block_const.timestamp,
            difficulty: block.block_const.difficulty,
            base_fee: block.block_const.base_fee,
            history_hashes: block.block_const.history_hashes.clone(),
        },
        rws: RwMap::from(&block.container),
        txs: block.txs().iter().map(tx_convert).collect(),
        bytecodes: block
            .txs()
            .iter()
            .flat_map(|tx| {
                tx.calls().iter().map(|call| {
                    Bytecode::new(
                        code_db.0.get(&call.code_hash).unwrap().to_vec(),
                    )
                })
            })
            .collect(),
    }
}

pub fn build_block(
    accounts: &[external_tracer::Account],
    eth_tx: bus_mapping::eth_types::Transaction,
) -> Block<Fp> {
    let tracer_tx = external_tracer::Transaction::from_eth_tx(&eth_tx);
    let geth_trace =
        external_tracer::trace(&Default::default(), &tracer_tx, accounts)
            .unwrap();

    let mut sdb = state_db::StateDB::new();
    let mut code_db = state_db::CodeDB::new();
    sdb.set_account(&eth_tx.from, state_db::Account::zero());
    for account in accounts {
        let code_hash = code_db.insert(account.code.to_vec());
        sdb.set_account(
            &account.address,
            state_db::Account {
                balance: account.balance,
                code_hash,
                ..state_db::Account::zero()
            },
        );
    }

    let mut builder = CircuitInputBuilder::new(
        sdb,
        code_db,
        Default::default(),
        Default::default(),
    );
    builder.handle_tx(&eth_tx, &geth_trace).unwrap();

    block_convert(&builder.block, &builder.code_db)
}

pub fn build_block_from_trace_code_at_start(
    bytecode: &bus_mapping::bytecode::Bytecode,
) -> Block<Fp> {
    let block =
        bus_mapping::mock::BlockData::new_single_tx_trace_code_at_start(
            bytecode,
        )
        .unwrap();
    let mut builder = block.new_circuit_input_builder();
    builder.handle_tx(&block.eth_tx, &block.geth_trace).unwrap();

    block_convert(&builder.block, &builder.code_db)
}
