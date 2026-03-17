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
        Box::new(BooleanityConstraint {
            column: TraceColumn::JnzTaken,
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
        Box::new(PcTransitionConstraint),
        Box::new(JnzPcTransitionConstraint),
        Box::new(JnzNonzeroImpliesTakenConstraint),
        Box::new(JnzInverseConstraint),
        Box::new(ConstTransitionConstraint),
        Box::new(MovTransitionConstraint),
        Box::new(AddTransitionConstraint),
        Box::new(SubTransitionConstraint),
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

fn lagrange_at_0_1_2_3<F: PrimeField>(x: F) -> (F, F, F, F) {
    let one = F::one();
    let two = F::from(2u64);
    let three = F::from(3u64);

    // Precomputed denominator inverses:
    // l0(x): denom = (0-1)(0-2)(0-3) = -6
    // l1(x): denom = (1-0)(1-2)(1-3) = 2
    // l2(x): denom = (2-0)(2-1)(2-3) = -2
    // l3(x): denom = (3-0)(3-1)(3-2) = 6
    let inv_neg_6 = (-F::from(6u64)).inverse().expect("nonzero");
    let inv_2 = F::from(2u64).inverse().expect("nonzero");
    let inv_neg_2 = (-F::from(2u64)).inverse().expect("nonzero");
    let inv_6 = F::from(6u64).inverse().expect("nonzero");

    let is_0 = (x - one) * (x - two) * (x - three) * inv_neg_6;
    let is_1 = x * (x - two) * (x - three) * inv_2;
    let is_2 = x * (x - one) * (x - three) * inv_neg_2;
    let is_3 = x * (x - one) * (x - two) * inv_6;

    (is_0, is_1, is_2, is_3)
}

fn a_selectors<F: PrimeField>(row: &dyn RowAccess<F>) -> (F, F, F, F) {
    let a = col(row, TraceColumn::A);
    lagrange_at_0_1_2_3(a)
}

fn prev_a_selectors<F: PrimeField>(row: &dyn RowAccess<F>) -> (F, F, F, F) {
    let a_prev = previous_col(row, TraceColumn::A);
    lagrange_at_0_1_2_3(a_prev)
}

fn reg_a<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    let (is_a_0, is_a_1, is_a_2, is_a_3) = a_selectors(row);

    let r0 = col(row, TraceColumn::R0);
    let r1 = col(row, TraceColumn::R1);
    let r2 = col(row, TraceColumn::R2);
    let r3 = col(row, TraceColumn::R3);

    is_a_0 * r0 + is_a_1 * r1 + is_a_2 * r2 + is_a_3 * r3
}

// get current value of previously used register in a
fn cur_reg_by_prev_a<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    let (is_a_0, is_a_1, is_a_2, is_a_3) = prev_a_selectors(row);

    let r0 = col(row, TraceColumn::R0);
    let r1 = col(row, TraceColumn::R1);
    let r2 = col(row, TraceColumn::R2);
    let r3 = col(row, TraceColumn::R3);

    is_a_0 * r0 + is_a_1 * r1 + is_a_2 * r2 + is_a_3 * r3
}

fn prev_reg_a<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    let (is_a_0, is_a_1, is_a_2, is_a_3) = prev_a_selectors(row);

    let r0_prev = previous_col(row, TraceColumn::R0);
    let r1_prev = previous_col(row, TraceColumn::R1);
    let r2_prev = previous_col(row, TraceColumn::R2);
    let r3_prev = previous_col(row, TraceColumn::R3);

    is_a_0 * r0_prev + is_a_1 * r1_prev + is_a_2 * r2_prev + is_a_3 * r3_prev
}

fn prev_b_selectors<F: PrimeField>(row: &dyn RowAccess<F>) -> (F, F, F, F) {
    let b_prev = previous_col(row, TraceColumn::B);
    lagrange_at_0_1_2_3(b_prev)
}

fn prev_reg_b<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    let (is_b_0, is_b_1, is_b_2, is_b_3) = prev_b_selectors(row);

    let r0_prev = previous_col(row, TraceColumn::R0);
    let r1_prev = previous_col(row, TraceColumn::R1);
    let r2_prev = previous_col(row, TraceColumn::R2);
    let r3_prev = previous_col(row, TraceColumn::R3);

    is_b_0 * r0_prev + is_b_1 * r1_prev + is_b_2 * r2_prev + is_b_3 * r3_prev
}

// get current value of previously used register in b
fn cur_reg_by_prev_b<F: PrimeField>(row: &dyn RowAccess<F>) -> F {
    let (is_b_0, is_b_1, is_b_2, is_b_3) = prev_b_selectors(row);

    let r0 = col(row, TraceColumn::R0);
    let r1 = col(row, TraceColumn::R1);
    let r2 = col(row, TraceColumn::R2);
    let r3 = col(row, TraceColumn::R3);

    is_b_0 * r0 + is_b_1 * r1 + is_b_2 * r2 + is_b_3 * r3
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

pub struct PcTransitionConstraint;

impl<F: PrimeField> Constraint<F> for PcTransitionConstraint {
    fn name(&self) -> String {
        "PC transition constraint".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let s_const = previous_col(row, SConst);
        let s_mov = previous_col(row, SMov);
        let s_add = previous_col(row, SAdd);
        let s_sub = previous_col(row, SSub);
        let s_jmp = previous_col(row, SJmp);
        let incrementing_ops = s_const + s_mov + s_add + s_sub;
        let s_halt = previous_col(row, SHalt);

        let pc = col(row, TraceColumn::Pc);
        let pc_prev = previous_col(row, TraceColumn::Pc);
        let target_prev = previous_col(row, TraceColumn::Target);

        transition_selector(row)
            * (incrementing_ops * (pc - pc_prev - F::one())
                + s_jmp * (pc - target_prev)
                + s_halt * (pc - pc_prev))
    }
}

pub struct JnzPcTransitionConstraint;

impl<F: PrimeField> Constraint<F> for JnzPcTransitionConstraint {
    fn name(&self) -> String {
        "jnz pc transition".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let s_jnz = previous_col(row, TraceColumn::SJnz);
        let taken = previous_col(row, TraceColumn::JnzTaken);

        let pc_prev = previous_col(row, TraceColumn::Pc);
        let pc_cur = col(row, TraceColumn::Pc);
        let target = previous_col(row, TraceColumn::Target);

        let expected_pc = taken * target + (F::one() - taken) * (pc_prev + F::one());

        (pc_cur - expected_pc) * s_jnz * transition_selector(row)
    }
}

pub struct JnzNonzeroImpliesTakenConstraint;

impl<F: PrimeField> Constraint<F> for JnzNonzeroImpliesTakenConstraint {
    fn name(&self) -> String {
        "jnz nonzero condition implies taken".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let s_jnz = previous_col(row, TraceColumn::SJnz);
        let taken = previous_col(row, TraceColumn::JnzTaken);
        let cond = prev_reg_a(row);

        cond * (F::one() - taken) * s_jnz * transition_selector(row)
    }
}

pub struct JnzInverseConstraint;

impl<F: PrimeField> Constraint<F> for JnzInverseConstraint {
    fn name(&self) -> String {
        "jnz inverse relation".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let s_jnz = previous_col(row, SJnz);
        let taken = previous_col(row, TraceColumn::JnzTaken);
        let inv = previous_col(row, TraceColumn::JnzTakenInv);
        let cond = prev_reg_a(row);

        (cond * inv - taken) * s_jnz * transition_selector(row)
    }
}

pub struct ConstTransitionConstraint;

impl<F: PrimeField> Constraint<F> for ConstTransitionConstraint {
    fn name(&self) -> String {
        "correct register transition after const".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let s_const = previous_col(row, SConst);
        let imm_prev = previous_col(row, TraceColumn::Imm);
        let dst_cur = cur_reg_by_prev_a(row);

        transition_selector(row) * s_const * (dst_cur - imm_prev)
    }
}

pub struct MovTransitionConstraint;

impl<F: PrimeField> Constraint<F> for MovTransitionConstraint {
    fn name(&self) -> String {
        "correct register transition after mov".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let s_mov = previous_col(row, SMov);
        let b_prev = prev_reg_b(row);
        let dst_cur = cur_reg_by_prev_a(row);

        transition_selector(row) * s_mov * (dst_cur - b_prev)
    }
}
pub struct AddTransitionConstraint;

impl<F: PrimeField> Constraint<F> for AddTransitionConstraint {
    fn name(&self) -> String {
        "correct register transition after add".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let s_add = previous_col(row, SAdd);
        let b_prev = prev_reg_b(row);
        let a_prev = prev_reg_a(row);
        let dst_cur = cur_reg_by_prev_a(row);

        transition_selector(row) * s_add * (dst_cur - (a_prev + b_prev))
    }
}
pub struct SubTransitionConstraint;

impl<F: PrimeField> Constraint<F> for SubTransitionConstraint {
    fn name(&self) -> String {
        "correct register transition after sub".to_string()
    }

    fn eval(&self, row: &dyn RowAccess<F>) -> F {
        let s_sub = previous_col(row, SSub);
        let b_prev = prev_reg_b(row);
        let a_prev = prev_reg_a(row);
        let dst_cur = cur_reg_by_prev_a(row);

        transition_selector(row) * s_sub * (dst_cur - (a_prev - b_prev))
    }
}
