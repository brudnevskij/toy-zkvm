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

    pub a: F,         // reg index (dst or cond)
    pub b: F,         // reg index (src)
    pub imm: F,       // immediate
    pub target: F,    // target pc
    pub jnz_taken: F, // jnz branching flag
    pub jnz_inv: F,   // jnz branching inverse
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
        jnz_taken: zero(),
        jnz_inv: zero(),
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

            // setting jnz flags
            let cond_value = state.regs[cond.idx()];
            if cond_value.is_zero() {
                row.jnz_taken = zero();
                row.jnz_inv = zero();
            } else {
                row.jnz_taken = one();
                row.jnz_inv = cond_value.inverse().unwrap();
            }
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
    JnzTaken,
    JnzTakenInv,
}

impl TraceColumn {
    pub const COUNT: usize = 20;

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
            Self::JnzTaken => 18,
            Self::JnzTakenInv => 19,
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
            Self::JnzTaken => "jnz taken",
            Self::JnzTakenInv => "jnz taken inverse",
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
            Self::JnzTaken,
            Self::JnzTakenInv,
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
        columns[TraceColumn::T.idx()].push(from_usize::<F>(i + 1));
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
        columns[TraceColumn::JnzTaken.idx()].push(row.jnz_taken);
        columns[TraceColumn::JnzTakenInv.idx()].push(row.jnz_inv);
    }

    TraceTable::new(columns, column_names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, fr};

    fn fr(x: u64) -> Fr {
        Fr::from(x)
    }

    fn base_state() -> VmState<Fr> {
        VmState {
            pc: 3,
            regs: [fr(10), fr(20), fr(30), fr(40)],
            halted: false,
        }
    }

    #[test]
    fn trace_column_layout_is_stable() {
        let all = TraceColumn::all();

        assert_eq!(all.len(), TraceColumn::COUNT);

        for (expected_idx, col) in all.into_iter().enumerate() {
            assert_eq!(col.idx(), expected_idx);
        }

        assert_eq!(TraceColumn::T.name(), "t");
        assert_eq!(TraceColumn::Pc.name(), "pc");
        assert_eq!(TraceColumn::R0.name(), "r0");
        assert_eq!(TraceColumn::R1.name(), "r1");
        assert_eq!(TraceColumn::R2.name(), "r2");
        assert_eq!(TraceColumn::R3.name(), "r3");
        assert_eq!(TraceColumn::Halted.name(), "halted");
        assert_eq!(TraceColumn::SConst.name(), "s_const");
        assert_eq!(TraceColumn::SMov.name(), "s_mov");
        assert_eq!(TraceColumn::SAdd.name(), "s_add");
        assert_eq!(TraceColumn::SSub.name(), "s_sub");
        assert_eq!(TraceColumn::SJmp.name(), "s_jmp");
        assert_eq!(TraceColumn::SJnz.name(), "s_jnz");
        assert_eq!(TraceColumn::SHalt.name(), "s_halt");
        assert_eq!(TraceColumn::A.name(), "a");
        assert_eq!(TraceColumn::B.name(), "b");
        assert_eq!(TraceColumn::Imm.name(), "imm");
        assert_eq!(TraceColumn::Target.name(), "target");
    }

    #[test]
    fn decode_row_const_sets_expected_fields() {
        let state = base_state();
        let row = decode_row(
            &state,
            &Instruction::Const {
                dst: Reg::R2,
                imm: 7,
            },
        );

        assert_eq!(row.pc, fr(3));
        assert_eq!(row.regs, [fr(10), fr(20), fr(30), fr(40)]);
        assert_eq!(row.halted, fr(0));

        assert_eq!(row.s_const, fr(1));
        assert_eq!(row.s_mov, fr(0));
        assert_eq!(row.s_add, fr(0));
        assert_eq!(row.s_sub, fr(0));
        assert_eq!(row.s_jmp, fr(0));
        assert_eq!(row.s_jnz, fr(0));
        assert_eq!(row.s_halt, fr(0));

        assert_eq!(row.a, fr(2));
        assert_eq!(row.b, fr(0));
        assert_eq!(row.imm, fr(7));
        assert_eq!(row.target, fr(0));
    }

    #[test]
    fn decode_row_mov_sets_expected_fields() {
        let state = base_state();
        let row = decode_row(
            &state,
            &Instruction::Mov {
                dst: Reg::R1,
                src: Reg::R3,
            },
        );

        assert_eq!(row.s_const, fr(0));
        assert_eq!(row.s_mov, fr(1));
        assert_eq!(row.s_add, fr(0));
        assert_eq!(row.s_sub, fr(0));
        assert_eq!(row.s_jmp, fr(0));
        assert_eq!(row.s_jnz, fr(0));
        assert_eq!(row.s_halt, fr(0));

        assert_eq!(row.a, fr(1));
        assert_eq!(row.b, fr(3));
        assert_eq!(row.imm, fr(0));
        assert_eq!(row.target, fr(0));
    }

    #[test]
    fn decode_row_add_sets_expected_fields() {
        let state = base_state();
        let row = decode_row(
            &state,
            &Instruction::Add {
                dst: Reg::R0,
                src: Reg::R2,
            },
        );

        assert_eq!(row.s_add, fr(1));
        assert_eq!(row.s_const, fr(0));
        assert_eq!(row.s_mov, fr(0));
        assert_eq!(row.s_sub, fr(0));
        assert_eq!(row.s_jmp, fr(0));
        assert_eq!(row.s_jnz, fr(0));
        assert_eq!(row.s_halt, fr(0));

        assert_eq!(row.a, fr(0));
        assert_eq!(row.b, fr(2));
        assert_eq!(row.imm, fr(0));
        assert_eq!(row.target, fr(0));
    }

    #[test]
    fn decode_row_sub_sets_expected_fields() {
        let state = base_state();
        let row = decode_row(
            &state,
            &Instruction::Sub {
                dst: Reg::R3,
                src: Reg::R1,
            },
        );

        assert_eq!(row.s_sub, fr(1));
        assert_eq!(row.s_const, fr(0));
        assert_eq!(row.s_mov, fr(0));
        assert_eq!(row.s_add, fr(0));
        assert_eq!(row.s_jmp, fr(0));
        assert_eq!(row.s_jnz, fr(0));
        assert_eq!(row.s_halt, fr(0));

        assert_eq!(row.a, fr(3));
        assert_eq!(row.b, fr(1));
        assert_eq!(row.imm, fr(0));
        assert_eq!(row.target, fr(0));
    }

    #[test]
    fn decode_row_jmp_sets_expected_fields() {
        let state = base_state();
        let row = decode_row(&state, &Instruction::Jmp { target: 11 });

        assert_eq!(row.s_jmp, fr(1));
        assert_eq!(row.s_const, fr(0));
        assert_eq!(row.s_mov, fr(0));
        assert_eq!(row.s_add, fr(0));
        assert_eq!(row.s_sub, fr(0));
        assert_eq!(row.s_jnz, fr(0));
        assert_eq!(row.s_halt, fr(0));

        assert_eq!(row.a, fr(0));
        assert_eq!(row.b, fr(0));
        assert_eq!(row.imm, fr(0));
        assert_eq!(row.target, fr(11));
    }

    #[test]
    fn decode_row_jnz_sets_expected_fields() {
        let state = base_state();
        let row = decode_row(
            &state,
            &Instruction::Jnz {
                cond: Reg::R1,
                target: 9,
            },
        );

        assert_eq!(row.s_jnz, fr(1));
        assert_eq!(row.s_const, fr(0));
        assert_eq!(row.s_mov, fr(0));
        assert_eq!(row.s_add, fr(0));
        assert_eq!(row.s_sub, fr(0));
        assert_eq!(row.s_jmp, fr(0));
        assert_eq!(row.s_halt, fr(0));

        assert_eq!(row.a, fr(1));
        assert_eq!(row.b, fr(0));
        assert_eq!(row.imm, fr(0));
        assert_eq!(row.target, fr(9));
    }

    #[test]
    fn decode_row_halt_sets_expected_fields() {
        let state = VmState {
            pc: 5,
            regs: [fr(1), fr(2), fr(3), fr(4)],
            halted: true,
        };
        let row = decode_row(&state, &Instruction::Halt);

        assert_eq!(row.pc, fr(5));
        assert_eq!(row.regs, [fr(1), fr(2), fr(3), fr(4)]);
        assert_eq!(row.halted, fr(1));

        assert_eq!(row.s_halt, fr(1));
        assert_eq!(row.s_const, fr(0));
        assert_eq!(row.s_mov, fr(0));
        assert_eq!(row.s_add, fr(0));
        assert_eq!(row.s_sub, fr(0));
        assert_eq!(row.s_jmp, fr(0));
        assert_eq!(row.s_jnz, fr(0));

        assert_eq!(row.a, fr(0));
        assert_eq!(row.b, fr(0));
        assert_eq!(row.imm, fr(0));
        assert_eq!(row.target, fr(0));
    }

    #[test]
    fn rows_to_trace_table_builds_column_major_trace() {
        let row0 = ExecutionRow {
            pc: fr(0),
            regs: [fr(10), fr(11), fr(12), fr(13)],
            halted: fr(0),
            s_const: fr(1),
            s_mov: fr(0),
            s_add: fr(0),
            s_sub: fr(0),
            s_jmp: fr(0),
            s_jnz: fr(0),
            s_halt: fr(0),
            a: fr(2),
            b: fr(0),
            imm: fr(7),
            target: fr(0),
            jnz_taken: fr(0),
            jnz_inv: fr(0),
        };

        let row1 = ExecutionRow {
            pc: fr(1),
            regs: [fr(20), fr(21), fr(22), fr(23)],
            halted: fr(1),
            s_const: fr(0),
            s_mov: fr(0),
            s_add: fr(0),
            s_sub: fr(0),
            s_jmp: fr(0),
            s_jnz: fr(0),
            s_halt: fr(1),
            a: fr(0),
            b: fr(0),
            imm: fr(0),
            target: fr(0),
            jnz_taken: fr(0),
            jnz_inv: fr(0),
        };

        let trace = rows_to_trace_table(&[row0, row1]);

        assert_eq!(trace.columns.len(), TraceColumn::COUNT);
        assert_eq!(trace.names.len(), TraceColumn::COUNT);

        assert_eq!(trace.names[TraceColumn::T.idx()], "t");
        assert_eq!(trace.names[TraceColumn::Pc.idx()], "pc");
        assert_eq!(trace.names[TraceColumn::Halted.idx()], "halted");
        assert_eq!(trace.names[TraceColumn::SConst.idx()], "s_const");
        assert_eq!(trace.names[TraceColumn::SHalt.idx()], "s_halt");
        assert_eq!(trace.names[TraceColumn::Imm.idx()], "imm");

        assert_eq!(trace.columns[TraceColumn::T.idx()], vec![fr(1), fr(2)]);
        assert_eq!(trace.columns[TraceColumn::Pc.idx()], vec![fr(0), fr(1)]);
        assert_eq!(trace.columns[TraceColumn::R0.idx()], vec![fr(10), fr(20)]);
        assert_eq!(trace.columns[TraceColumn::R1.idx()], vec![fr(11), fr(21)]);
        assert_eq!(trace.columns[TraceColumn::R2.idx()], vec![fr(12), fr(22)]);
        assert_eq!(trace.columns[TraceColumn::R3.idx()], vec![fr(13), fr(23)]);
        assert_eq!(trace.columns[TraceColumn::Halted.idx()], vec![fr(0), fr(1)]);
        assert_eq!(trace.columns[TraceColumn::SConst.idx()], vec![fr(1), fr(0)]);
        assert_eq!(trace.columns[TraceColumn::SMov.idx()], vec![fr(0), fr(0)]);
        assert_eq!(trace.columns[TraceColumn::SAdd.idx()], vec![fr(0), fr(0)]);
        assert_eq!(trace.columns[TraceColumn::SSub.idx()], vec![fr(0), fr(0)]);
        assert_eq!(trace.columns[TraceColumn::SJmp.idx()], vec![fr(0), fr(0)]);
        assert_eq!(trace.columns[TraceColumn::SJnz.idx()], vec![fr(0), fr(0)]);
        assert_eq!(trace.columns[TraceColumn::SHalt.idx()], vec![fr(0), fr(1)]);
        assert_eq!(trace.columns[TraceColumn::A.idx()], vec![fr(2), fr(0)]);
        assert_eq!(trace.columns[TraceColumn::B.idx()], vec![fr(0), fr(0)]);
        assert_eq!(trace.columns[TraceColumn::Imm.idx()], vec![fr(7), fr(0)]);
        assert_eq!(trace.columns[TraceColumn::Target.idx()], vec![fr(0), fr(0)]);
    }

    #[test]
    fn decode_row_jnz_nonzero_cond_sets_taken_and_inverse() {
        let state = base_state(); // r1 = 20
        let row = decode_row(
            &state,
            &Instruction::Jnz {
                cond: Reg::R1,
                target: 9,
            },
        );

        assert_eq!(row.s_jnz, fr(1));
        assert_eq!(row.a, fr(1));
        assert_eq!(row.target, fr(9));

        assert_eq!(row.jnz_taken, fr(1));
        assert_eq!(row.jnz_inv * fr(20), fr(1));
    }

    #[test]
    fn decode_row_jnz_zero_cond_sets_not_taken_and_zero_inverse() {
        let state = VmState {
            pc: 3,
            regs: [fr(10), fr(0), fr(30), fr(40)],
            halted: false,
        };

        let row = decode_row(
            &state,
            &Instruction::Jnz {
                cond: Reg::R1,
                target: 9,
            },
        );

        assert_eq!(row.s_jnz, fr(1));
        assert_eq!(row.a, fr(1));
        assert_eq!(row.target, fr(9));

        assert_eq!(row.jnz_taken, fr(0));
        assert_eq!(row.jnz_inv, fr(0));
    }
}
