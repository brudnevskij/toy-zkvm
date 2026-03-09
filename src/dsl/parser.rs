use crate::{
    dsl::{Keyword, ParsedInstr, Statement, Token},
    vm::Reg,
};

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
        let mut program = Vec::new();
        loop {
            match self.peek() {
                Some(Token::Newline) => {
                    self.advance();
                }
                Some(Token::Eof) => break,
                Some(_) => {
                    if let Some(stmnt) = self.parse_statement()? {
                        program.push(stmnt);
                    }
                }
                None => return Err(ParseError::UnexpectedEof),
            }
        }
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

    fn parse_column(&mut self) -> Result<(), ParseError> {
        match self.advance() {
            Some(Token::Punctuation(p)) if p == ":" => Ok(()),
            Some(t) => Err(ParseError::UnexpectedToken {
                expected: ":",
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
    fn parse_reg_reg_operands(&mut self) -> Result<(Reg, Reg), ParseError> {
        let lhs = self.parse_register()?;
        self.parse_comma()?;
        let rhs = self.parse_register()?;
        Ok((lhs, rhs))
    }

    fn parse_identifier(&mut self) -> Result<String, ParseError> {
        match self.advance() {
            Some(Token::Identifier(name)) => Ok(name.clone()),
            Some(t) => Err(ParseError::UnexpectedToken {
                expected: "identifier",
                found: t.clone(),
            }),
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

                    self.parse_comma()?;

                    let constant: u64 = match self.advance() {
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
                    self.advance();
                    let (register_l, register_r) = self.parse_reg_reg_operands()?;
                    Ok(Some(Statement::Instr(ParsedInstr::Mov(
                        register_l, register_r,
                    ))))
                }
                Keyword::Add => {
                    self.advance();
                    let (register_l, register_r) = self.parse_reg_reg_operands()?;
                    Ok(Some(Statement::Instr(ParsedInstr::Add(
                        register_l, register_r,
                    ))))
                }
                Keyword::Sub => {
                    self.advance();
                    let (register_l, register_r) = self.parse_reg_reg_operands()?;
                    Ok(Some(Statement::Instr(ParsedInstr::Sub(
                        register_l, register_r,
                    ))))
                }

                Keyword::Jmp => {
                    self.advance();
                    let identifier = self.parse_identifier()?;
                    Ok(Some(Statement::Instr(ParsedInstr::Jmp(identifier))))
                }
                Keyword::Jnz => {
                    self.advance();

                    let register = self.parse_register()?;
                    self.parse_comma()?;
                    let identifier = self.parse_identifier()?;

                    Ok(Some(Statement::Instr(ParsedInstr::Jnz(
                        register, identifier,
                    ))))
                }
                Keyword::Halt => {
                    self.advance();
                    Ok(Some(Statement::Instr(ParsedInstr::Halt)))
                }
            },
            Some(Token::Identifier(identifier)) => {
                let identifier = identifier.clone();
                self.advance();
                self.parse_column()?;
                Ok(Some(Statement::Label(identifier)))
            }

            Some(Token::Newline) => Ok(None),
            Some(Token::Eof) => Ok(None),

            Some(token) => Err(ParseError::UnexpectedToken {
                expected: "keyword or label",
                found: token.clone(),
            }),

            None => Err(ParseError::UnexpectedEof),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::Lexer;

    fn parse_ok(src: &str) -> Vec<Statement> {
        let mut lexer = Lexer::new(src);
        let tokens = lexer.lex().expect("lexer should succeed");

        let mut parser = Parser::new(tokens);
        parser.parse().expect("parser should succeed")
    }

    fn parse_err(src: &str) -> ParseError {
        let mut lexer = Lexer::new(src);
        let tokens = lexer.lex().expect("lexer should succeed");

        let mut parser = Parser::new(tokens);
        parser.parse().expect_err("parser should fail")
    }

    #[test]
    fn parse_halt_only() {
        let program = parse_ok("halt\n");

        assert_eq!(program, vec![Statement::Instr(ParsedInstr::Halt)]);
    }

    #[test]
    fn parse_const_instruction() {
        let program = parse_ok("const r0, 8\n");

        assert_eq!(
            program,
            vec![Statement::Instr(ParsedInstr::Const(Reg::R0, 8))]
        );
    }

    #[test]
    fn parse_mov_add_sub_instructions() {
        let src = "
mov r0, r1
add r2, r3
sub r1, r0
";
        let program = parse_ok(src);

        assert_eq!(
            program,
            vec![
                Statement::Instr(ParsedInstr::Mov(Reg::R0, Reg::R1)),
                Statement::Instr(ParsedInstr::Add(Reg::R2, Reg::R3)),
                Statement::Instr(ParsedInstr::Sub(Reg::R1, Reg::R0)),
            ]
        );
    }

    #[test]
    fn parse_jmp_and_jnz() {
        let src = "
jmp loop
jnz r0, loop
";
        let program = parse_ok(src);

        assert_eq!(
            program,
            vec![
                Statement::Instr(ParsedInstr::Jmp("loop".to_string())),
                Statement::Instr(ParsedInstr::Jnz(Reg::R0, "loop".to_string())),
            ]
        );
    }

    #[test]
    fn parse_label_only_line() {
        let program = parse_ok("loop:\n");

        assert_eq!(program, vec![Statement::Label("loop".to_string())]);
    }

    #[test]
    fn parse_label_and_instruction_sequence() {
        let src = "
loop:
add r1, r0
jnz r0, loop
halt
";
        let program = parse_ok(src);

        assert_eq!(
            program,
            vec![
                Statement::Label("loop".to_string()),
                Statement::Instr(ParsedInstr::Add(Reg::R1, Reg::R0)),
                Statement::Instr(ParsedInstr::Jnz(Reg::R0, "loop".to_string())),
                Statement::Instr(ParsedInstr::Halt),
            ]
        );
    }

    #[test]
    fn parse_ignores_empty_lines() {
        let src = "\n\nhalt\n\n";
        let program = parse_ok(src);

        assert_eq!(program, vec![Statement::Instr(ParsedInstr::Halt)]);
    }

    #[test]
    fn parse_with_comments_via_lexer() {
        let src = "
# start
const r0, 3   # initialize
loop:
sub r0, r1
jnz r0, loop
halt
";
        let program = parse_ok(src);

        assert_eq!(
            program,
            vec![
                Statement::Instr(ParsedInstr::Const(Reg::R0, 3)),
                Statement::Label("loop".to_string()),
                Statement::Instr(ParsedInstr::Sub(Reg::R0, Reg::R1)),
                Statement::Instr(ParsedInstr::Jnz(Reg::R0, "loop".to_string())),
                Statement::Instr(ParsedInstr::Halt),
            ]
        );
    }

    #[test]
    fn parse_invalid_register_in_const() {
        let err = parse_err("const r9, 1\n");

        match err {
            ParseError::InvalidRegister(name) => assert_eq!(name, "r9"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_missing_comma_in_const() {
        let err = parse_err("const r0 1\n");

        match err {
            ParseError::UnexpectedToken { expected, found } => {
                assert_eq!(expected, ",");
                assert_eq!(found, Token::Number(1));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_missing_colon_after_label() {
        let err = parse_err("loop\n");

        match err {
            ParseError::UnexpectedToken { expected, .. } => {
                assert_eq!(expected, ":");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_jmp_requires_identifier_label() {
        let err = parse_err("jmp 123\n");

        match err {
            ParseError::UnexpectedToken { expected, found } => {
                assert_eq!(expected, "identifier");
                assert_eq!(found, Token::Number(123));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_jnz_requires_register_then_label() {
        let err = parse_err("jnz foo, loop\n");

        match err {
            ParseError::InvalidRegister(name) => assert_eq!(name, "foo"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_unexpected_token_at_statement_start() {
        // A line starting with a comma is not a valid statement.
        let err = parse_err(",\n");

        match err {
            ParseError::UnexpectedToken { expected, found } => {
                assert_eq!(expected, "keyword or label");
                assert_eq!(found, Token::Punctuation(",".to_string()));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
