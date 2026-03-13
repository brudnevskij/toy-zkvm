use ark_ff::PrimeField;

pub mod trace;
pub use trace::TraceTable;

pub trait RowAccess<F: PrimeField> {
    fn current_step_column_value(&self, column: usize) -> F;
    fn previous_step_column_value(&self, column: usize) -> F;

    fn idx(&self) -> usize;
    fn x(&self) -> F;
    fn x0(&self) -> F;
    fn x_last(&self) -> F;
    fn z_h_inverse(&self) -> F;

    fn first_row_selector(&self) -> F;
    fn last_row_selector(&self) -> F;
}

pub trait Constraint<F: PrimeField>: Send + Sync {
    fn name(&self) -> String;
    fn eval(&self, row: &dyn RowAccess<F>) -> F;
}

pub trait Air<F: PrimeField> {
    fn width(&self) -> usize;

    fn column_name(&self, _col: usize) -> String {
        "col".to_string()
    }

    fn num_constraints(&self) -> usize;

    fn eval_constraint(&self, i: usize, row: &dyn RowAccess<F>) -> F;

    fn constraint_name(&self, _i: usize) -> String {
        "constraint".to_string()
    }
}

pub fn eval_composition<F: PrimeField>(
    air: &impl Air<F>,
    row: &dyn RowAccess<F>,
    alphas: &[F],
) -> F {
    assert_eq!(alphas.len(), air.num_constraints());
    let mut acc = F::zero();
    for i in 0..air.num_constraints() {
        acc += alphas[i] * air.eval_constraint(i, row);
    }
    acc
}
