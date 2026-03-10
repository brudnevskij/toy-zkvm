mod ast;
mod lexer;
mod parser;
mod resolver;

pub use ast::{ParsedInstr, Statement};
pub use lexer::{Keyword, LexError, Lexer, Token};
pub use parser::{ParseError, Parser};
pub use resolver::{ResolveError, Resolver};
use thiserror::Error;

use crate::vm::Program;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    #[error("lex error: {0}")]
    Lex(#[from] LexError),

    #[error("parse error: {0}")]
    Parse(#[from] ParseError),

    #[error("resolve error: {0}")]
    Resolve(#[from] ResolveError),
}

pub fn compile(source: &str) -> Result<Program, CompileError> {
    let tokens = Lexer::new(source).lex()?;
    let ast = Parser::new(tokens).parse()?;
    let program = Resolver::resolve(&ast)?;
    Ok(program)
}
