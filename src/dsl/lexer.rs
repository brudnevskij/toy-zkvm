use core::str;
use std::char;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Punctuation(String),
    Keyword(Keyword),
    Identifier(String),
    Number(u64),
    Newline,
    Eof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Keyword {
    Const,
    Mov,
    Add,
    Sub,
    Jmp,
    Jnz,
    Halt,
}

fn keyword_of(s: &str) -> Option<Keyword> {
    match s {
        "const" => Some(Keyword::Const),
        "mov" => Some(Keyword::Mov),
        "add" => Some(Keyword::Add),
        "sub" => Some(Keyword::Sub),
        "jmp" => Some(Keyword::Jmp),
        "jnz" => Some(Keyword::Jnz),
        "halt" => Some(Keyword::Halt),
        _ => None,
    }
}

#[derive(Error, Debug)]
pub enum LexError {
    #[error("unknown character {0}")]
    UnknownCharacter(char),
}

pub struct Lexer<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Lexer<'a> {
        Self { src, pos: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    fn skip_comment(&mut self) {
        while let Some(c) = self.peek() {
            if c == '\n' {
                break;
            }
            self.pos += 1;
        }
    }

    pub fn lex(&mut self) -> Result<Vec<Token>, LexError> {
        let mut token_stream = Vec::new();

        loop {
            if let Some(c) = self.peek() {
                match c {
                    ',' | ':' => {
                        token_stream.push(Token::Punctuation(c.to_string()));
                        self.pos += 1;
                    }

                    '0'..='9' | 'a'..='z' | 'A'..='Z' | '_' => {
                        let mut word = c.to_string();
                        self.pos += 1;

                        // collecting word
                        while let Some(c) = self.peek() {
                            if c.is_alphanumeric() || c == '_' {
                                word.push(c);
                                self.pos += 1;
                            } else {
                                break;
                            }
                        }

                        if let Some(keyword) = keyword_of(&word) {
                            token_stream.push(Token::Keyword(keyword));
                        } else {
                            let token = match word.parse::<u64>() {
                                Ok(number) => Token::Number(number),
                                Err(_) => Token::Identifier(word),
                            };

                            token_stream.push(token);
                        }
                    }

                    '\n' => {
                        token_stream.push(Token::Newline);
                        self.pos += 1;
                    }

                    ' ' | '\t' | '\r' => self.pos += 1,

                    '#' => self.skip_comment(),

                    c => return Err(LexError::UnknownCharacter(c)),
                }
            } else {
                token_stream.push(Token::Eof);
                break;
            }
        }

        Ok(token_stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lex_ok(src: &str) -> Vec<Token> {
        let mut lexer = Lexer::new(src);
        lexer.lex().expect("lexer should succeed")
    }

    #[test]
    fn lex_single_halt() {
        let tokens = lex_ok("halt");

        assert_eq!(tokens, vec![Token::Keyword(Keyword::Halt), Token::Eof,]);
    }

    #[test]
    fn lex_basic_instruction_with_whitespace() {
        let tokens = lex_ok("const r0, 8\n");

        assert_eq!(
            tokens,
            vec![
                Token::Keyword(Keyword::Const),
                Token::Identifier("r0".to_string()),
                Token::Punctuation(",".to_string()),
                Token::Number(8),
                Token::Newline,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn lex_label_and_jump() {
        let tokens = lex_ok("loop:\njmp loop\n");

        assert_eq!(
            tokens,
            vec![
                Token::Identifier("loop".to_string()),
                Token::Punctuation(":".to_string()),
                Token::Newline,
                Token::Keyword(Keyword::Jmp),
                Token::Identifier("loop".to_string()),
                Token::Newline,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn lex_jnz_line() {
        let tokens = lex_ok("jnz r0, loop\n");

        assert_eq!(
            tokens,
            vec![
                Token::Keyword(Keyword::Jnz),
                Token::Identifier("r0".to_string()),
                Token::Punctuation(",".to_string()),
                Token::Identifier("loop".to_string()),
                Token::Newline,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn lex_ignores_spaces_tabs_and_carriage_return() {
        let tokens = lex_ok(" \tconst\t r1,\r 42 \n");

        assert_eq!(
            tokens,
            vec![
                Token::Keyword(Keyword::Const),
                Token::Identifier("r1".to_string()),
                Token::Punctuation(",".to_string()),
                Token::Number(42),
                Token::Newline,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn lex_comment_only_line() {
        let tokens = lex_ok("# this is a comment\nhalt");

        assert_eq!(
            tokens,
            vec![Token::Newline, Token::Keyword(Keyword::Halt), Token::Eof,]
        );
    }

    #[test]
    fn lex_inline_comment_preserves_newline() {
        let tokens = lex_ok("const r0, 1 # comment here\nhalt\n");

        assert_eq!(
            tokens,
            vec![
                Token::Keyword(Keyword::Const),
                Token::Identifier("r0".to_string()),
                Token::Punctuation(",".to_string()),
                Token::Number(1),
                Token::Newline,
                Token::Keyword(Keyword::Halt),
                Token::Newline,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn lex_multiple_lines_program() {
        let src = "\
const r0, 3
const r1, 0
add r1, r0
halt
";
        let tokens = lex_ok(src);

        assert_eq!(
            tokens,
            vec![
                Token::Keyword(Keyword::Const),
                Token::Identifier("r0".to_string()),
                Token::Punctuation(",".to_string()),
                Token::Number(3),
                Token::Newline,
                Token::Keyword(Keyword::Const),
                Token::Identifier("r1".to_string()),
                Token::Punctuation(",".to_string()),
                Token::Number(0),
                Token::Newline,
                Token::Keyword(Keyword::Add),
                Token::Identifier("r1".to_string()),
                Token::Punctuation(",".to_string()),
                Token::Identifier("r0".to_string()),
                Token::Newline,
                Token::Keyword(Keyword::Halt),
                Token::Newline,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn lex_unknown_character_returns_error() {
        let mut lexer = Lexer::new("@");
        let err = lexer.lex().expect_err("lexer should fail on unknown char");

        match err {
            // If you rename the variant to UnknownCharacter, update this match arm.
            LexError::UnknownCharacter('@') => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
