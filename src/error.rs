use std::fmt::Display;

#[derive(Debug, PartialEq)]
pub enum BIP32Error {
    /// More than 128 bits, less than 256 bits and be a multiple of 32
    InvalidEntropy,

    /// Error when reading the language words
    ReadFile(String),

    /// Coutn number doesn't match
    InvalidWordsCount(usize),

    BitReader(String),

    //No word found at selected index
    WordNotFound(u16),

    HexEncode(String),
}

impl BIP32Error {
    pub fn message(&self) -> String {
        match self {
            BIP32Error::InvalidEntropy => String::from("Entropy not valid. It should be more than 128 bits, less than 256 bits and be a multiple of 32"),
            BIP32Error::ReadFile(error) => String::from(format!("Error when reading file : {}", error)),
            BIP32Error::InvalidWordsCount(nb) => String::from(format!("The words count ({}) is not valid", nb)),
            BIP32Error::BitReader(error) => String::from(format!("Error while reading bit : {}", error)),
            BIP32Error::WordNotFound(index) => String::from(format!("No word found at selected index {}", index)),
            BIP32Error::HexEncode(error) => String::from(format!("Error when trying to encode hexadecimal {}", error)),
        }
    }
}

impl Display for BIP32Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}