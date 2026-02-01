use ark_ff::PrimeField;

pub mod air;
pub mod trace;

pub trait RowAccess<F: PrimeField> {
    fn current_step_column_value(&self, column: usize) -> F;
    fn previous_step_column_value(&self, column: usize) -> F;

    fn x(&self) -> F;
    fn x0(&self) -> F;
    fn x_last(&self) -> F;
    fn z_h_inverse(&self) -> F;
}

pub type ConstraintFunction<F> = fn(&dyn RowAccess<F>) -> F;

pub trait Air<F: PrimeField> {
    fn width(&self) -> usize;

    fn column_name(&self, _col: usize) -> &'static str {
        "col"
    }

    fn num_constraints(&self) -> usize;

    fn eval_constraint(&self, i: usize, row: &dyn RowAccess<F>) -> F;

    fn constraint_name(&self, _i: usize) -> &'static str {
        "constraint"
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
