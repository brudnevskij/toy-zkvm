use crate::vm::Reg;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedInstr {
    Const(Reg, u64),
    Mov(Reg, Reg),
    Add(Reg, Reg),
    Sub(Reg, Reg),
    Jmp(String),
    Jnz(Reg, String),
    Halt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Statement {
    Label(String),
    Instr(ParsedInstr),
}
