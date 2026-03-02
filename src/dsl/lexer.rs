use core::str;
use std::char;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Punctuation(String),
    Keyword(Keyword),
    Identifier(String),
    Number(i64),
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
                            let token = match word.parse::<i64>() {
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
