use core::error;
use std::usize;

use ark_ff::PrimeField;
use thiserror::Error;

use crate::vm::{ExecutionRow, Instruction, Pc, Program, decode_row};

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

    #[error("execution did not halt before trace filled, trace_len: {trace_len}")]
    StepLimitExceeded { trace_len: usize },
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

pub fn run_rows<F: PrimeField>(
    initial_state: VmState<F>,
    program: &Program,
    trace_len: usize,
    max_steps: usize,
) -> Result<Vec<ExecutionRow<F>>, VmError> {
    assert!(
        trace_len.is_power_of_two(),
        "trace length must be power of two"
    );
    let mut execution_rows = Vec::with_capacity(trace_len);

    let mut steps = 0usize;
    let mut state = initial_state;
    while execution_rows.len() < trace_len {
        if state.halted {
            let row = decode_row(&state, &Instruction::Halt);
            execution_rows.push(row);
            continue;
        }

        if steps >= max_steps {
            return Err(VmError::StepLimitExceeded {
                trace_len: max_steps,
            });
        }

        let instr = program
            .instructions
            .get(state.pc)
            .ok_or(VmError::PcOutOfBounds {
                pc: state.pc,
                program_len: program.instructions.len(),
            })?;

        execution_rows.push(decode_row(&state, instr));

        state = step(&state, program)?;
        steps += 1;
    }

    Ok(execution_rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{Instruction, Program, Reg};
    use ark_bn254::Fr;
    use ark_ff::{One, PrimeField, Zero};

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

    fn init_state<F: PrimeField>() -> VmState<F> {
        VmState {
            pc: 0,
            regs: [F::zero(); 4],
            halted: false,
        }
    }

    fn state_with_r0<F: PrimeField>(r0: u64) -> VmState<F> {
        let mut s = init_state::<F>();
        s.regs[Reg::R0.idx()] = fe_u64::<F>(r0);
        s
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
        assert!(!st1.halted);
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

    #[test]
    fn run_rows_returns_exact_trace_len() {
        let program = Program {
            instructions: vec![Instruction::Halt],
        };

        let rows = run_rows::<Fr>(init_state(), &program, 8, 100).expect("run should succeed");
        assert_eq!(rows.len(), 8);
    }

    #[test]
    fn row0_is_pre_state() {
        // Program: const r0, 7; halt
        let program = Program {
            instructions: vec![
                Instruction::Const {
                    dst: Reg::R0,
                    imm: 7,
                },
                Instruction::Halt,
            ],
        };

        let rows = run_rows::<Fr>(init_state(), &program, 8, 100).expect("run should succeed");

        // Row 0 is pre-state: r0 should still be 0
        assert_eq!(rows[0].regs[Reg::R0.idx()], Fr::zero());
        // And selector should be const
        assert_eq!(rows[0].s_const, Fr::one());
        assert_eq!(rows[0].s_halt, Fr::zero());

        // Row 1 is pre-state for halt, so r0 should be 7 there
        assert_eq!(rows[1].regs[Reg::R0.idx()], fe_u64::<Fr>(7));
        assert_eq!(rows[1].s_halt, Fr::one());
    }

    #[test]
    fn halting_pads_with_halt_rows() {
        // Program halts immediately
        let program = Program {
            instructions: vec![Instruction::Halt],
        };

        let rows = run_rows::<Fr>(init_state(), &program, 8, 100).expect("run should succeed");
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(row.s_halt, Fr::one(), "row {i} should be halt");
            if i == 0 {
                assert_eq!(row.halted, Fr::zero());
            } else {
                assert_eq!(row.halted, Fr::one());
            }
        }
    }

    #[test]
    fn executes_simple_program_then_pads() {
        // const r0, 5
        // const r1, 2
        // add r0, r1
        // halt
        let program = Program {
            instructions: vec![
                Instruction::Const {
                    dst: Reg::R0,
                    imm: 5,
                },
                Instruction::Const {
                    dst: Reg::R1,
                    imm: 2,
                },
                Instruction::Add {
                    dst: Reg::R0,
                    src: Reg::R1,
                },
                Instruction::Halt,
            ],
        };

        let rows = run_rows::<Fr>(init_state(), &program, 8, 100).expect("run should succeed");

        // Pre-state checks:
        // Row 0 (before const r0,5): r0=0
        assert_eq!(rows[0].regs[Reg::R0.idx()], Fr::zero());
        assert_eq!(rows[0].s_const, Fr::one());

        // Row 1 (before const r1,2): r0=5, r1=0
        assert_eq!(rows[1].regs[Reg::R0.idx()], fe_u64::<Fr>(5));
        assert_eq!(rows[1].regs[Reg::R1.idx()], Fr::zero());

        // Row 2 (before add): r0=5, r1=2
        assert_eq!(rows[2].regs[Reg::R0.idx()], fe_u64::<Fr>(5));
        assert_eq!(rows[2].regs[Reg::R1.idx()], fe_u64::<Fr>(2));
        assert_eq!(rows[2].s_add, Fr::one());

        // Row 3 (before halt): r0=7
        assert_eq!(rows[3].regs[Reg::R0.idx()], fe_u64::<Fr>(7));
        assert_eq!(rows[3].s_halt, Fr::one());

        // Rows 4.. are padding halts and must keep r0=7
        for i in 4..8 {
            assert_eq!(rows[i].s_halt, Fr::one());
            assert_eq!(rows[i].regs[Reg::R0.idx()], fe_u64::<Fr>(7));
        }
    }

    #[test]
    fn step_limit_exceeded_errors() {
        // Infinite loop: jmp 0
        let program = Program {
            instructions: vec![Instruction::Jmp { target: 0 }],
        };

        let err = run_rows::<Fr>(init_state(), &program, 8, 3).expect_err("should error");
        assert_eq!(err, VmError::StepLimitExceeded { trace_len: 3 });
    }

    #[test]
    fn pc_out_of_bounds_errors() {
        // Jump to invalid pc
        let program = Program {
            instructions: vec![Instruction::Jmp { target: 999 }],
        };

        // trace_len=8 so it will try to execute and then fail on next fetch
        let err = run_rows::<Fr>(init_state(), &program, 8, 100).expect_err("should error");

        match err {
            VmError::PcOutOfBounds { pc, program_len } => {
                assert_eq!(pc, 999);
                assert_eq!(program_len, 1);
            }
            other => panic!("expected PcOutOfBounds, got {other:?}"),
        }
    }
}
