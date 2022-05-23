use std::fmt::Display;

///
/// Represent all errors that can happen during the program
/// 
#[derive(Debug, PartialEq)]
pub enum BIP32Error {
    /// More than 128 bits, less than 256 bits and be a multiple of 32
    InvalidEntropy,

    /// Error when reading the language words
    ReadFile(String),

    /// Count number doesn't match
    InvalidWordsCount(usize),

    /// Error while reading bit
    BitReader(String),

    ///No word found at selected index
    WordNotFound(u16),

    /// Error when trying to encode or decode from / hex
    HexError(String),
}

impl BIP32Error {
    pub fn message(&self) -> String {
        match self {
            BIP32Error::InvalidEntropy => String::from("Entropy not valid. It should be more than 128 bits, less than 256 bits and be a multiple of 32"),
            BIP32Error::ReadFile(error) => String::from(format!("Error when reading file : {}", error)),
            BIP32Error::InvalidWordsCount(nb) => String::from(format!("The words count ({}) is not valid", nb)),
            BIP32Error::BitReader(error) => String::from(format!("Error while reading bit : {}", error)),
            BIP32Error::WordNotFound(index) => String::from(format!("No word found at selected index {}", index)),
            BIP32Error::HexError(error) => String::from(format!("Error when trying to encode or decode hexadecimal {}", error)),
        }
    }
}

impl Display for BIP32Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Use default message
        write!(f, "{}", self.message())
    }
}