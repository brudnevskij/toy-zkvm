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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::{ParsedInstr, Statement};
    use crate::vm::{Instruction, Program, Reg};

    fn resolve(stmts: Vec<Statement>) -> Result<Program, ResolveError> {
        Resolver::resolve(&stmts)
    }

    #[test]
    fn resolves_backward_jump_to_label() {
        // loop:
        // add r1, r0
        // jmp loop
        let program = resolve(vec![
            Statement::Label("loop".to_string()),
            Statement::Instr(ParsedInstr::Add(Reg::R1, Reg::R0)),
            Statement::Instr(ParsedInstr::Jmp("loop".to_string())),
        ])
        .expect("should resolve");

        // label "loop" points to PC=0 (first instruction)
        assert_eq!(
            program.instructions,
            vec![
                Instruction::Add {
                    dst: Reg::R1,
                    src: Reg::R0
                },
                Instruction::Jmp { target: 0 },
            ]
        );
    }

    #[test]
    fn resolves_forward_jump_to_label() {
        // jmp end
        // const r0, 7
        // end:
        // halt
        let program = resolve(vec![
            Statement::Instr(ParsedInstr::Jmp("end".to_string())),
            Statement::Instr(ParsedInstr::Const(Reg::R0, 7)),
            Statement::Label("end".to_string()),
            Statement::Instr(ParsedInstr::Halt),
        ])
        .expect("should resolve forward jump");

        // instruction PCs:
        // 0: jmp end  -> target 2
        // 1: const
        // 2: halt
        assert_eq!(
            program.instructions,
            vec![
                Instruction::Jmp { target: 2 },
                Instruction::Const {
                    dst: Reg::R0,
                    imm: 7
                },
                Instruction::Halt,
            ]
        );
    }

    #[test]
    fn label_does_not_increment_pc() {
        // const r0, 1
        // L:
        // const r1, 2
        // jmp L
        let program = resolve(vec![
            Statement::Instr(ParsedInstr::Const(Reg::R0, 1)),
            Statement::Label("L".to_string()),
            Statement::Instr(ParsedInstr::Const(Reg::R1, 2)),
            Statement::Instr(ParsedInstr::Jmp("L".to_string())),
        ])
        .expect("should resolve");

        // instruction PCs:
        // 0: const r0, 1
        // 1: const r1, 2   <- label L points here
        // 2: jmp L         <- target must be 1
        assert_eq!(
            program.instructions,
            vec![
                Instruction::Const {
                    dst: Reg::R0,
                    imm: 1
                },
                Instruction::Const {
                    dst: Reg::R1,
                    imm: 2
                },
                Instruction::Jmp { target: 1 },
            ]
        );
    }

    #[test]
    fn resolves_jnz_target() {
        // loop:
        // jnz r0, loop
        let program = resolve(vec![
            Statement::Label("loop".to_string()),
            Statement::Instr(ParsedInstr::Jnz(Reg::R0, "loop".to_string())),
        ])
        .expect("should resolve");

        assert_eq!(
            program.instructions,
            vec![Instruction::Jnz {
                cond: Reg::R0,
                target: 0
            }]
        );
    }

    #[test]
    fn missing_label_is_error_for_jmp() {
        let err = resolve(vec![Statement::Instr(ParsedInstr::Jmp("nope".to_string()))])
            .expect_err("should fail");

        match err {
            ResolveError::MissingLabel { expected_label } => assert_eq!(expected_label, "nope"),
            other => panic!("expected MissingLabel, got {other:?}"),
        }
    }

    #[test]
    fn missing_label_is_error_for_jnz() {
        let err = resolve(vec![Statement::Instr(ParsedInstr::Jnz(
            Reg::R0,
            "nope".to_string(),
        ))])
        .expect_err("should fail");

        match err {
            ResolveError::MissingLabel { expected_label } => assert_eq!(expected_label, "nope"),
            other => panic!("expected MissingLabel, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_label_is_error() {
        let err = resolve(vec![
            Statement::Label("L".to_string()),
            Statement::Instr(ParsedInstr::Halt),
            Statement::Label("L".to_string()), // duplicate
            Statement::Instr(ParsedInstr::Halt),
        ])
        .expect_err("should fail");

        match err {
            ResolveError::DuplicateLabel { name } => assert_eq!(name, "L"),
            other => panic!("expected DuplicateLabel, got {other:?}"),
        }
    }

    #[test]
    fn multiple_labels_can_point_to_same_pc() {
        // A:
        // B:
        // halt
        //
        // Both labels should resolve to PC=0; this is valid.
        let program = resolve(vec![
            Statement::Label("A".to_string()),
            Statement::Label("B".to_string()),
            Statement::Instr(ParsedInstr::Halt),
        ])
        .expect("should resolve");

        assert_eq!(program.instructions, vec![Instruction::Halt]);
    }

    #[test]
    fn empty_program_resolves_to_empty_instructions() {
        let program = resolve(vec![]).expect("empty program should resolve");
        assert!(program.instructions.is_empty());
    }

    #[test]
    fn label_only_program_resolves_to_empty_instructions() {
        let program = resolve(vec![
            Statement::Label("A".to_string()),
            Statement::Label("B".to_string()),
        ])
        .expect("label-only should resolve");

        assert!(program.instructions.is_empty());
    }
}
