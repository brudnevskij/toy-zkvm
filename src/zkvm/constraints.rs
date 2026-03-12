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
        Box::new(InitPcConstraint),
        Box::new(InitR0Constraint),
        Box::new(InitR1Constraint),
        Box::new(InitR2Constraint),
        Box::new(InitR3Constraint),
        Box::new(InitHaltedConstraint),
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

fn first_row_selector<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    if row.idx() == 0 { F::one() } else { F::zero() }
}

fn transition_selector<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    if row.idx() == 0 { F::zero() } else { F::one() }
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

pub struct InitPcConstraint;

impl<F: PrimeField> Constraint<F> for InitPcConstraint {
    fn name(&self) -> String {
        "initial pc is zero".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        col(row, TraceColumn::Pc) * first_row_selector(row)
    }
}

pub struct InitR0Constraint;

impl<F: PrimeField> Constraint<F> for InitR0Constraint {
    fn name(&self) -> String {
        "initial r0 is zero".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        col(row, TraceColumn::R0) * first_row_selector(row)
    }
}

pub struct InitR1Constraint;

impl<F: PrimeField> Constraint<F> for InitR1Constraint {
    fn name(&self) -> String {
        "initial r1 is zero".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        col(row, TraceColumn::R1) * first_row_selector(row)
    }
}

pub struct InitR2Constraint;

impl<F: PrimeField> Constraint<F> for InitR2Constraint {
    fn name(&self) -> String {
        "initial r2 is zero".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        col(row, TraceColumn::R2) * first_row_selector(row)
    }
}

pub struct InitR3Constraint;

impl<F: PrimeField> Constraint<F> for InitR3Constraint {
    fn name(&self) -> String {
        "initial r3 is zero".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        col(row, TraceColumn::R3) * first_row_selector(row)
    }
}

pub struct InitHaltedConstraint;

impl<F: PrimeField> Constraint<F> for InitHaltedConstraint {
    fn name(&self) -> String {
        "initial halted is zero".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        col(row, TraceColumn::Halted) * first_row_selector(row)
    }
}
