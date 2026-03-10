use ark_ff::PrimeField;

use crate::vm::{Instruction, Reg, VmState};

#[derive(Debug, Clone)]
pub struct ExecutionRow<F: PrimeField> {
    pub pc: F,
    pub regs: [F; 4],
    pub halted: F,

    // decoded instruction info for AIR
    pub s_const: F,
    pub s_mov: F,
    pub s_add: F,
    pub s_sub: F,
    pub s_jmp: F,
    pub s_jnz: F,
    pub s_halt: F,

    pub a: F,      // reg index (dst or cond)
    pub b: F,      // reg index (src)
    pub imm: F,    // immediate
    pub target: F, // target pc
}

fn zero<F: PrimeField>() -> F {
    F::zero()
}

fn one<F: PrimeField>() -> F {
    F::one()
}

fn from_usize<F: PrimeField>(n: usize) -> F {
    fe_u64::<F>(n as u64)
}

fn from_bool<F: PrimeField>(b: bool) -> F {
    if b { F::one() } else { F::zero() }
}

fn fe_u64<F: PrimeField>(x: u64) -> F {
    F::from_le_bytes_mod_order(&x.to_le_bytes())
}

fn fe_reg<F: PrimeField>(r: Reg) -> F {
    fe_u64::<F>(r.idx() as u64)
}

pub fn decode_row<F: PrimeField>(state: &VmState<F>, instr: &Instruction) -> ExecutionRow<F> {
    let mut row = ExecutionRow {
        pc: from_usize(state.pc),
        regs: state.regs,
        halted: from_bool(state.halted),

        s_const: zero(),
        s_mov: zero(),
        s_add: zero(),
        s_sub: zero(),
        s_jmp: zero(),
        s_jnz: zero(),
        s_halt: zero(),

        a: zero(),
        b: zero(),
        imm: zero(),
        target: zero(),
    };

    match instr {
        Instruction::Const { dst, imm } => {
            row.s_const = one();
            row.a = fe_reg::<F>(*dst);
            row.imm = fe_u64::<F>(*imm);
        }
        Instruction::Mov { dst, src } => {
            row.s_mov = one();
            row.a = fe_reg::<F>(*dst);
            row.b = fe_reg::<F>(*src);
        }
        Instruction::Add { dst, src } => {
            row.s_add = one();
            row.a = fe_reg::<F>(*dst);
            row.b = fe_reg::<F>(*src);
        }
        Instruction::Sub { dst, src } => {
            row.s_sub = one();
            row.a = fe_reg::<F>(*dst);
            row.b = fe_reg::<F>(*src);
        }
        Instruction::Jmp { target } => {
            row.s_jmp = one();
            row.target = from_usize(*target);
        }
        Instruction::Jnz { cond, target } => {
            row.s_jnz = one();
            row.a = fe_reg::<F>(*cond);
            row.target = from_usize(*target);
        }
        Instruction::Halt => {
            row.s_halt = one();
        }
    }

    row
}
