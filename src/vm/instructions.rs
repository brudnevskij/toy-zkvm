#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reg {
    R0,
    R1,
    R2,
    R3,
}

impl Reg {
    pub const fn idx(self) -> usize {
        match self {
            Reg::R0 => 0,
            Reg::R1 => 1,
            Reg::R2 => 2,
            Reg::R3 => 3,
        }
    }
}

pub type Pc = usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    Const { dst: Reg, imm: i64 },
    Mov { dst: Reg, src: Reg },
    Add { dst: Reg, src: Reg },
    Sub { dst: Reg, src: Reg },
    Jmp { target: Pc },
    Jnz { cond: Reg, target: Pc },
    Halt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub instructions: Vec<Instruction>,
}
