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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{Instruction, Program, Reg};
    use ark_bn254::Fr;
    use ark_ff::{PrimeField, Zero};

    fn fe_u64<F: PrimeField>(x: u64) -> F {
        F::from_le_bytes_mod_order(&x.to_le_bytes())
    }

    fn s<F: PrimeField>(pc: usize, r0: F, r1: F, r2: F, r3: F, halted: bool) -> VmState<F> {
        VmState {
            pc,
            regs: [r0, r1, r2, r3],
            halted,
        }
    }

    #[test]
    fn const_sets_register_and_increments_pc() {
        let program = Program {
            instructions: vec![Instruction::Const {
                dst: Reg::R2,
                imm: 42,
            }],
        };

        let st0 = s::<Fr>(0, Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero(), false);
        let st1 = step(&st0, &program).expect("step should succeed");

        assert_eq!(st1.pc, 1);
        assert!(!st1.halted);
        assert_eq!(st1.regs[Reg::R2.idx()], fe_u64::<Fr>(42));
        // other regs unchanged
        assert_eq!(st1.regs[Reg::R0.idx()], Fr::zero());
        assert_eq!(st1.regs[Reg::R1.idx()], Fr::zero());
        assert_eq!(st1.regs[Reg::R3.idx()], Fr::zero());
    }

    #[test]
    fn mov_copies_register_and_increments_pc() {
        let program = Program {
            instructions: vec![Instruction::Mov {
                dst: Reg::R1,
                src: Reg::R3,
            }],
        };

        let st0 = s::<Fr>(
            0,
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
            fe_u64::<Fr>(9),
            false,
        );
        let st1 = step(&st0, &program).expect("step should succeed");

        assert_eq!(st1.pc, 1);
        assert_eq!(st1.regs[Reg::R1.idx()], fe_u64::<Fr>(9));
        assert_eq!(st1.regs[Reg::R3.idx()], fe_u64::<Fr>(9));
    }

    #[test]
    fn add_updates_dst_only() {
        let program = Program {
            instructions: vec![Instruction::Add {
                dst: Reg::R0,
                src: Reg::R2,
            }],
        };

        let st0 = s::<Fr>(
            0,
            fe_u64::<Fr>(10),
            fe_u64::<Fr>(1),
            fe_u64::<Fr>(7),
            fe_u64::<Fr>(3),
            false,
        );
        let st1 = step(&st0, &program).expect("step should succeed");

        assert_eq!(st1.pc, 1);
        assert_eq!(st1.regs[Reg::R0.idx()], fe_u64::<Fr>(17));
        // unchanged regs
        assert_eq!(st1.regs[Reg::R1.idx()], fe_u64::<Fr>(1));
        assert_eq!(st1.regs[Reg::R2.idx()], fe_u64::<Fr>(7));
        assert_eq!(st1.regs[Reg::R3.idx()], fe_u64::<Fr>(3));
    }

    #[test]
    fn sub_updates_dst_only() {
        let program = Program {
            instructions: vec![Instruction::Sub {
                dst: Reg::R0,
                src: Reg::R1,
            }],
        };

        // 10 - 3 = 7
        let st0 = s::<Fr>(
            0,
            fe_u64::<Fr>(10),
            fe_u64::<Fr>(3),
            Fr::zero(),
            Fr::zero(),
            false,
        );
        let st1 = step(&st0, &program).expect("step should succeed");

        assert_eq!(st1.pc, 1);
        assert_eq!(st1.regs[Reg::R0.idx()], fe_u64::<Fr>(7));
        assert_eq!(st1.regs[Reg::R1.idx()], fe_u64::<Fr>(3));
    }

    #[test]
    fn jmp_sets_pc_to_target() {
        let program = Program {
            instructions: vec![Instruction::Jmp { target: 7 }],
        };

        let st0 = s::<Fr>(0, Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero(), false);
        let st1 = step(&st0, &program).expect("step should succeed");

        assert_eq!(st1.pc, 7);
        assert!(st1.halted);
    }

    #[test]
    fn jnz_not_taken_increments_pc() {
        let program = Program {
            instructions: vec![Instruction::Jnz {
                cond: Reg::R0,
                target: 9,
            }],
        };

        let st0 = s::<Fr>(0, Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero(), false);
        let st1 = step(&st0, &program).expect("step should succeed");

        assert_eq!(st1.pc, 1);
    }

    #[test]
    fn jnz_taken_jumps_to_target() {
        let program = Program {
            instructions: vec![Instruction::Jnz {
                cond: Reg::R0,
                target: 9,
            }],
        };

        let st0 = s::<Fr>(
            0,
            fe_u64::<Fr>(1),
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
            false,
        );
        let st1 = step(&st0, &program).expect("step should succeed");

        assert_eq!(st1.pc, 9);
    }

    #[test]
    fn halt_sets_halted_and_freezes_pc() {
        let program = Program {
            instructions: vec![Instruction::Halt],
        };

        let st0 = s::<Fr>(
            0,
            fe_u64::<Fr>(5),
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
            false,
        );
        let st1 = step(&st0, &program).expect("step should succeed");

        assert!(st1.halted);
        assert_eq!(st1.pc, 0);
        assert_eq!(st1.regs[Reg::R0.idx()], fe_u64::<Fr>(5));
    }

    #[test]
    fn stepping_when_halted_is_noop() {
        let program = Program {
            instructions: vec![Instruction::Const {
                dst: Reg::R0,
                imm: 999,
            }],
        };

        let st0 = s::<Fr>(0, fe_u64::<Fr>(5), Fr::zero(), Fr::zero(), Fr::zero(), true);
        let st1 = step(&st0, &program).expect("step should succeed (noop)");

        assert_eq!(st1, st0);
    }

    #[test]
    fn pc_out_of_bounds_returns_error() {
        let program = Program {
            instructions: vec![],
        };

        let st0 = s::<Fr>(0, Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero(), false);
        let err = step(&st0, &program).expect_err("should fail");

        assert_eq!(
            err,
            VmError::PcOutOfBounds {
                pc: 0,
                program_len: 0
            }
        );
    }
}
