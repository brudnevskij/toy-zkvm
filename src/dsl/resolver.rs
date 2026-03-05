use thiserror::Error;

use crate::{
    dsl::{ParsedInstr, Statement},
    vm::{Instruction, Pc, Program},
};
use std::collections::HashMap;

#[derive(Error, Debug)]
pub enum ResolveError {
    #[error("jumping to non-existent label: {expected_label}")]
    MissingLabel { expected_label: String },

    #[error("duplicate label: {name}")]
    DuplicateLabel { name: String },
}

pub struct Resolver;

impl Resolver {
    pub fn resolve(parsed_program: &[Statement]) -> Result<Program, ResolveError> {
        let mut labels: HashMap<String, Pc> = HashMap::new();
        let mut pc: Pc = 0;

        for stmnt in parsed_program {
            match stmnt {
                Statement::Label(name) => {
                    if labels.insert(name.clone(), pc).is_some() {
                        return Err(ResolveError::DuplicateLabel { name: name.clone() });
                    }
                }
                Statement::Instr(_) => {
                    pc += 1;
                }
            }
        }

        let mut instructions = Vec::new();

        for stmnt in parsed_program {
            if let Statement::Instr(parsed_instr) = stmnt {
                let instr = match parsed_instr {
                    ParsedInstr::Const(reg, imm) => Instruction::Const {
                        dst: *reg,
                        imm: *imm,
                    },
                    ParsedInstr::Mov(dst, src) => Instruction::Mov {
                        dst: *dst,
                        src: *src,
                    },
                    ParsedInstr::Add(dst, src) => Instruction::Add {
                        dst: *dst,
                        src: *src,
                    },
                    ParsedInstr::Sub(dst, src) => Instruction::Sub {
                        dst: *dst,
                        src: *src,
                    },
                    ParsedInstr::Jmp(target) => {
                        let addr =
                            *labels
                                .get(target)
                                .ok_or_else(|| ResolveError::MissingLabel {
                                    expected_label: target.clone(),
                                })?;
                        Instruction::Jmp { target: addr }
                    }
                    ParsedInstr::Jnz(reg, target) => {
                        let addr =
                            *labels
                                .get(target)
                                .ok_or_else(|| ResolveError::MissingLabel {
                                    expected_label: target.clone(),
                                })?;
                        Instruction::Jnz {
                            cond: *reg,
                            target: addr,
                        }
                    }
                    ParsedInstr::Halt => Instruction::Halt,
                };

                instructions.push(instr);
            }
        }

        Ok(Program { instructions })
    }
}
