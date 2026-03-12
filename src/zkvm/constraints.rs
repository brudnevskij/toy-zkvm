use ark_ff::PrimeField;

use crate::{
    air::{Constraint, RowAccess},
    vm::{
        TraceColumn,
        TraceColumn::{SAdd, SConst, SHalt, SJmp, SJnz, SMov, SSub},
    },
};

fn col<F: PrimeField>(row: &dyn RowAccess<F>, c: TraceColumn) -> F {
    row.current_step_column_value(c.idx())
}

fn reg_index_vanishing<F: PrimeField>(x: F) -> F {
    x * (x - F::one()) * (x - F::from(2u64)) * (x - F::from(3u64))
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
