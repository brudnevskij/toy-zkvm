#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reg {
    R0,
    R1,
    R2,
    R3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedInstr {
    Const(Reg, i64),
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
