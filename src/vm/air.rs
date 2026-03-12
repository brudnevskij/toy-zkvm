use ark_ff::PrimeField;

use crate::{
    air::{Air, Constraint, RowAccess},
    vm::TraceColumn,
    zkvm::build_vm_constraints,
};

pub struct VmAir<F: PrimeField> {
    constraints: Vec<Box<dyn Constraint<F>>>,
}

impl<F: PrimeField> VmAir<F> {
    pub fn from_constraints(constraints: Vec<Box<dyn Constraint<F>>>) -> Self {
        Self { constraints }
    }

    pub fn constraints(&self) -> &[Box<dyn Constraint<F>>] {
        &self.constraints
    }
}

impl<F: PrimeField> Default for VmAir<F> {
    fn default() -> Self {
        Self {
            constraints: build_vm_constraints(),
        }
    }
}

impl<F: PrimeField> Air<F> for VmAir<F> {
    fn width(&self) -> usize {
        TraceColumn::COUNT
    }

    fn column_name(&self, col: usize) -> String {
        TraceColumn::all()[col].name().to_string()
    }

    fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    fn eval_constraint(&self, i: usize, row: &dyn RowAccess<F>) -> F {
        self.constraints[i].eval(row) * row.z_h_inverse()
    }

    fn constraint_name(&self, i: usize) -> String {
        self.constraints[i].name()
    }
}
