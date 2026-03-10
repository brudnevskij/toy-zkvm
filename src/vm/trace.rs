use ark_ff::PrimeField;

use crate::{
    air::TraceTable,
    vm::{Instruction, Reg, VmState},
};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceColumn {
    T,
    Pc,
    R0,
    R1,
    R2,
    R3,
    Halted,
    SConst,
    SMov,
    SAdd,
    SSub,
    SJmp,
    SJnz,
    SHalt,
    A,
    B,
    Imm,
    Target,
}

impl TraceColumn {
    pub const COUNT: usize = 18;

    pub const fn idx(self) -> usize {
        match self {
            Self::T => 0,
            Self::Pc => 1,
            Self::R0 => 2,
            Self::R1 => 3,
            Self::R2 => 4,
            Self::R3 => 5,
            Self::Halted => 6,
            Self::SConst => 7,
            Self::SMov => 8,
            Self::SAdd => 9,
            Self::SSub => 10,
            Self::SJmp => 11,
            Self::SJnz => 12,
            Self::SHalt => 13,
            Self::A => 14,
            Self::B => 15,
            Self::Imm => 16,
            Self::Target => 17,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::T => "t",
            Self::Pc => "pc",
            Self::R0 => "r0",
            Self::R1 => "r1",
            Self::R2 => "r2",
            Self::R3 => "r3",
            Self::Halted => "halted",
            Self::SConst => "s_const",
            Self::SMov => "s_mov",
            Self::SAdd => "s_add",
            Self::SSub => "s_sub",
            Self::SJmp => "s_jmp",
            Self::SJnz => "s_jnz",
            Self::SHalt => "s_halt",
            Self::A => "a",
            Self::B => "b",
            Self::Imm => "imm",
            Self::Target => "target",
        }
    }

    pub fn all() -> [Self; Self::COUNT] {
        [
            Self::T,
            Self::Pc,
            Self::R0,
            Self::R1,
            Self::R2,
            Self::R3,
            Self::Halted,
            Self::SConst,
            Self::SMov,
            Self::SAdd,
            Self::SSub,
            Self::SJmp,
            Self::SJnz,
            Self::SHalt,
            Self::A,
            Self::B,
            Self::Imm,
            Self::Target,
        ]
    }
}

pub fn rows_to_trace_table<F: PrimeField>(rows: &[ExecutionRow<F>]) -> TraceTable<F> {
    let trace_len = rows.len();

    let column_names = TraceColumn::all()
        .into_iter()
        .map(|c| c.name().to_string())
        .collect::<Vec<_>>();

    let mut columns: Vec<Vec<F>> = (0..TraceColumn::COUNT)
        .map(|_| Vec::with_capacity(trace_len))
        .collect();

    for (i, row) in rows.iter().enumerate() {
        columns[TraceColumn::T.idx()].push(from_usize::<F>(i));
        columns[TraceColumn::Pc.idx()].push(row.pc);
        columns[TraceColumn::R0.idx()].push(row.regs[0]);
        columns[TraceColumn::R1.idx()].push(row.regs[1]);
        columns[TraceColumn::R2.idx()].push(row.regs[2]);
        columns[TraceColumn::R3.idx()].push(row.regs[3]);
        columns[TraceColumn::Halted.idx()].push(row.halted);

        columns[TraceColumn::SConst.idx()].push(row.s_const);
        columns[TraceColumn::SMov.idx()].push(row.s_mov);
        columns[TraceColumn::SAdd.idx()].push(row.s_add);
        columns[TraceColumn::SSub.idx()].push(row.s_sub);
        columns[TraceColumn::SJmp.idx()].push(row.s_jmp);
        columns[TraceColumn::SJnz.idx()].push(row.s_jnz);
        columns[TraceColumn::SHalt.idx()].push(row.s_halt);

        columns[TraceColumn::A.idx()].push(row.a);
        columns[TraceColumn::B.idx()].push(row.b);
        columns[TraceColumn::Imm.idx()].push(row.imm);
        columns[TraceColumn::Target.idx()].push(row.target);
    }

    TraceTable::new(columns, column_names)
}
