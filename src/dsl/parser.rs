use std::{fmt::format, i64};

use crate::dsl::{Keyword, Token};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reg {
    R0,
    R1,
    R2,
    R3,
}

fn register_of(name: &str) -> Result<Reg, ParseError> {
    match name {
        "r0" => Ok(Reg::R0),
        "r1" => Ok(Reg::R1),
        "r2" => Ok(Reg::R2),
        "r3" => Ok(Reg::R3),
        n => Err(ParseError::InvalidRegister(n.to_string())),
    }
}

fn parse_register(token: &Token) -> Result<Reg, ParseError> {
    match token {
        Token::Identifier(name) => register_of(name),
        t => Err(ParseError::InvalidRegister(format!("{:?}", t))),
    }
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

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("unexpected token: expected {expected}, found {found:?}")]
    UnexpectedToken {
        expected: &'static str,
        found: Token,
    },

    #[error("invalid register name: {0}")]
    InvalidRegister(String),

    #[error("expected label after jump, found {0:?}")]
    ExpectedLabel(Token),

    #[error("unexpected end of input")]
    UnexpectedEof,
}

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Parser {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.pos);
        if token.is_some() {
            self.pos += 1;
        }
        token
    }

    pub fn parse(&mut self) -> Result<Vec<Statement>, ParseError> {
        let program = Vec::new();

        Ok(program)
    }

    fn parse_comma(&mut self) -> Result<(), ParseError> {
        match self.advance() {
            Some(Token::Punctuation(p)) if p == "," => Ok(()),
            Some(t) => Err(ParseError::UnexpectedToken {
                expected: ",",
                found: t.clone(),
            }),
            None => Err(ParseError::UnexpectedEof),
        }
    }

    fn parse_register(&mut self) -> Result<Reg, ParseError> {
        match self.advance() {
            Some(token) => parse_register(token),
            None => Err(ParseError::UnexpectedEof),
        }
    }

    fn parse_statement(&mut self) -> Result<Option<Statement>, ParseError> {
        match self.peek() {
            Some(Token::Keyword(k)) => match k {
                Keyword::Const => {
                    // consume const
                    self.advance();

                    let register = self.parse_register()?;

                    self.parse_coma()?;

                    let constant: i64 = match self.advance() {
                        Some(Token::Number(n)) => *n,
                        Some(t) => {
                            return Err(ParseError::UnexpectedToken {
                                expected: "Number",
                                found: t.clone(),
                            });
                        }
                        None => return Err(ParseError::UnexpectedEof),
                    };

                    Ok(Some(Statement::Instr(ParsedInstr::Const(
                        register, constant,
                    ))))
                }
                Keyword::Mov => {
                    // consume Mov
                    self.advance();

                    let register_l = self.parse_register()?;

                    self.parse_coma()?;

                    let register_r = self.parse_register()?;

                    Ok(Some(Statement::Instr(ParsedInstr::Mov(
                        register_l, register_r,
                    ))))
                }
                Keyword::Add => todo!(),
                Keyword::Sub => todo!(),
                Keyword::Jmp => todo!(),
                Keyword::Jnz => todo!(),
                Keyword::Halt => todo!(),
            },
            _ => Ok(None),
        }
    }
}
