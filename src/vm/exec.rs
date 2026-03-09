use ark_ff::PrimeField;
use thiserror::Error;

use crate::vm::{Instruction, Pc, Program};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmState<F: PrimeField> {
    pub pc: Pc,
    pub regs: [F; 4],
    pub halted: bool,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum VmError {
    #[error("pc is out of bounds, pc: {pc} program length: {program_len}")]
    PcOutOfBounds { pc: usize, program_len: usize },
}

pub fn step<F: PrimeField>(state: &VmState<F>, program: &Program) -> Result<VmState<F>, VmError> {
    if state.halted {
        return Ok(*state);
    }

    let instr = program
        .instructions
        .get(state.pc)
        .ok_or(VmError::PcOutOfBounds {
            pc: state.pc,
            program_len: program.instructions.len(),
        })?;

    match instr {
        Instruction::Const { dst, imm } => {
            let mut regs = state.regs;
            regs[dst.idx()] = F::from_le_bytes_mod_order(&imm.to_le_bytes());
            Ok(VmState {
                pc: state.pc + 1,
                regs,
                halted: state.halted,
            })
        }

        Instruction::Mov { dst, src } => {
            let mut regs = state.regs;
            regs[dst.idx()] = state.regs[src.idx()];
            Ok(VmState {
                pc: state.pc + 1,
                regs,
                halted: state.halted,
            })
        }

        Instruction::Add { dst, src } => {
            let mut regs = state.regs;
            regs[dst.idx()] = state.regs[dst.idx()] + state.regs[src.idx()];
            Ok(VmState {
                pc: state.pc + 1,
                regs,
                halted: state.halted,
            })
        }

        Instruction::Sub { dst, src } => {
            let mut regs = state.regs;
            regs[dst.idx()] = state.regs[dst.idx()] - state.regs[src.idx()];
            Ok(VmState {
                pc: state.pc + 1,
                regs,
                halted: state.halted,
            })
        }

        Instruction::Jmp { target } => Ok(VmState {
            pc: *target,
            regs: state.regs,
            halted: state.halted,
        }),

        Instruction::Jnz { cond, target } => {
            let pc = if state.regs[cond.idx()] == F::zero() {
                state.pc + 1
            } else {
                *target
            };
            Ok(VmState {
                pc,
                regs: state.regs,
                halted: state.halted,
            })
        }

        Instruction::Halt => Ok(VmState {
            pc: state.pc,
            regs: state.regs,
            halted: true,
        }),
    }
}
