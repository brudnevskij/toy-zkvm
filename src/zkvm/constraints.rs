use std::fmt::format;

use ark_ff::PrimeField;

use crate::{
    air::{Constraint, RowAccess},
    vm::{
        TraceColumn,
        TraceColumn::{SAdd, SConst, SHalt, SJmp, SJnz, SMov, SSub},
    },
};

pub fn build_vm_constraints<F: PrimeField>() -> Vec<Box<dyn Constraint<F>>> {
    vec![
        Box::new(BooleanityConstraint {
            column: TraceColumn::Halted,
        }),
        Box::new(BooleanityConstraint {
            column: TraceColumn::SConst,
        }),
        Box::new(BooleanityConstraint {
            column: TraceColumn::SMov,
        }),
        Box::new(BooleanityConstraint {
            column: TraceColumn::SAdd,
        }),
        Box::new(BooleanityConstraint {
            column: TraceColumn::SSub,
        }),
        Box::new(BooleanityConstraint {
            column: TraceColumn::SJmp,
        }),
        Box::new(BooleanityConstraint {
            column: TraceColumn::SJnz,
        }),
        Box::new(BooleanityConstraint {
            column: TraceColumn::SHalt,
        }),
        Box::new(OneHotOpcode),
        Box::new(RegisterIndexValidity {
            column: TraceColumn::A,
        }),
        Box::new(RegisterIndexValidity {
            column: TraceColumn::B,
        }),
        Box::new(UnusedOperandsConstraint),
        Box::new(InitZeroConstraint {
            column: TraceColumn::Pc,
        }),
        Box::new(InitZeroConstraint {
            column: TraceColumn::R0,
        }),
        Box::new(InitZeroConstraint {
            column: TraceColumn::R1,
        }),
        Box::new(InitZeroConstraint {
            column: TraceColumn::R2,
        }),
        Box::new(InitZeroConstraint {
            column: TraceColumn::R3,
        }),
        Box::new(InitZeroConstraint {
            column: TraceColumn::Halted,
        }),
        Box::new(HaltedFreezeConstraint),
        Box::new(HaltEntryConstraint),
    ]
}

fn col<F: PrimeField>(row: &dyn RowAccess<F>, c: TraceColumn) -> F {
    row.current_step_column_value(c.idx())
}

fn previous_col<F: PrimeField>(row: &dyn RowAccess<F>, c: TraceColumn) -> F {
    row.previous_step_column_value(c.idx())
}

fn reg_index_vanishing<F: PrimeField>(x: F) -> F {
    x * (x - F::one()) * (x - F::from(2u64)) * (x - F::from(3u64))
}

fn transition_selector<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    F::one() - row.first_row_selector()
}

pub struct BooleanityConstraint {
    pub column: TraceColumn,
}

impl<F: PrimeField> Constraint<F> for BooleanityConstraint {
    fn name(&self) -> String {
        format!("booleanity of column {}", self.column.name())
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let x = col(row, self.column);
        x * (x - F::one())
    }
}

pub struct OneHotOpcode;

impl<F: PrimeField> Constraint<F> for OneHotOpcode {
    fn name(&self) -> String {
        "one-hot encoding constraint of instructions".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let s_const = col(row, SConst);
        let s_mov = col(row, SMov);
        let s_add = col(row, SAdd);
        let s_sub = col(row, SSub);
        let s_jmp = col(row, SJmp);
        let s_jnz = col(row, SJnz);
        let s_halt = col(row, SHalt);

        s_const + s_mov + s_add + s_sub + s_jmp + s_jnz + s_halt - F::one()
    }
}

pub struct RegisterIndexValidity {
    pub column: TraceColumn,
}

impl RegisterIndexValidity {
    fn operand_selector<F: PrimeField>(&self, row: &dyn RowAccess<F>) -> F {
        let s_const = col(row, SConst);
        let s_mov = col(row, SMov);
        let s_add = col(row, SAdd);
        let s_sub = col(row, SSub);
        let s_jnz = col(row, SJnz);

        match self.column {
            TraceColumn::A => s_const + s_mov + s_add + s_sub + s_jnz,
            TraceColumn::B => s_mov + s_add + s_sub,
            _ => panic!("RegisterIndexValidity only supports columns A and B"),
        }
    }
}

impl<F: PrimeField> Constraint<F> for RegisterIndexValidity {
    fn name(&self) -> String {
        format!("register index validity for {}", self.column.name())
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let x = col(row, self.column);
        self.operand_selector(row) * reg_index_vanishing(x)
    }
}

pub struct UnusedOperandsConstraint;

impl<F: PrimeField> Constraint<F> for UnusedOperandsConstraint {
    fn name(&self) -> String {
        "zeroing constraint for unused operands".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let s_const = col(row, SConst);
        let s_mov = col(row, SMov);
        let s_add = col(row, SAdd);
        let s_sub = col(row, SSub);
        let s_jmp = col(row, SJmp);
        let s_jnz = col(row, SJnz);
        let s_halt = col(row, SHalt);

        let a = col(row, TraceColumn::A);
        let b = col(row, TraceColumn::B);
        let imm = col(row, TraceColumn::Imm);
        let target = col(row, TraceColumn::Target);

        // const
        s_const * b
            + s_const * target
        // mov
            + s_mov * imm
            + s_mov * target
        // add
            + s_add * imm
            + s_add * target
        // sub
            + s_sub * imm
            + s_sub * target
        // jmp
            + s_jmp * a
            + s_jmp * b
            + s_jmp * imm
        // jzn
            + s_jnz * b
            + s_jnz * imm
        // halt
            + s_halt * a
            + s_halt * b
            + s_halt * imm
            + s_halt * target
    }
}

pub struct InitZeroConstraint {
    pub column: TraceColumn,
}

impl<F: PrimeField> Constraint<F> for InitZeroConstraint {
    fn name(&self) -> String {
        format!("init 0 constraint for {}", self.column.name())
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        col(row, self.column) * row.first_row_selector()
    }
}

pub struct HaltedFreezeConstraint;

impl<F: PrimeField> Constraint<F> for HaltedFreezeConstraint {
    fn name(&self) -> String {
        "machine stays frozen after halt".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let transition = transition_selector(row);

        let halted = col(row, TraceColumn::Halted);
        let halted_prev = previous_col(row, TraceColumn::Halted);

        let pc = col(row, TraceColumn::Pc);
        let pc_prev = previous_col(row, TraceColumn::Pc);

        let r0 = col(row, TraceColumn::R0);
        let r0_prev = previous_col(row, TraceColumn::R0);

        let r1 = col(row, TraceColumn::R1);
        let r1_prev = previous_col(row, TraceColumn::R1);

        let r2 = col(row, TraceColumn::R2);
        let r2_prev = previous_col(row, TraceColumn::R2);

        let r3 = col(row, TraceColumn::R3);
        let r3_prev = previous_col(row, TraceColumn::R3);

        transition
            * (halted_prev * (halted - F::one())
                + halted_prev * (pc - pc_prev)
                + halted_prev * (r0 - r0_prev)
                + halted_prev * (r1 - r1_prev)
                + halted_prev * (r2 - r2_prev)
                + halted_prev * (r3 - r3_prev))
    }
}

pub struct HaltEntryConstraint;

impl<F: PrimeField> Constraint<F> for HaltEntryConstraint {
    fn name(&self) -> String {
        "enforece halt opcode behaviour".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let s_halt_prev = previous_col(row, SHalt);
        let halted = col(row, TraceColumn::Halted);
        (s_halt_prev * (halted - F::one())) * transition_selector(row)
    }
}
