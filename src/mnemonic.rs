use std::{fmt::Display, u8};

use crate::{
    entropy::{Bytes, Entropy, EntropySize},
    error::BIP32Error,
    language::{Language, Words},
    utils, BITS_LEN_ITERATION,
};
use bitreader::BitReader;


///
/// Represent the BIP39 Mnemonic phrase
/// 
pub struct Mnemonic {
    mnemonic_words: Vec<String>,
    entropy: Entropy,
}

impl Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.get_phrase())
    }
}

impl Mnemonic {
    /// 
    /// Create a mnemonic from the given entropy size
    /// 
    pub fn create(entropy_size: EntropySize, lang: Language) -> Result<Mnemonic, BIP32Error> {
        Mnemonic::from_entropy(Entropy::generate(entropy_size), lang)
    }

    ///
    /// Create a mnemonic from an existing entropy
    /// 
    pub fn from_entropy(mut entropy: Entropy, lang: Language) -> Result<Mnemonic, BIP32Error> {
        // Load all words from current language
        let words = Words::load(lang)?;

        // Generate list of mnemonic vector string
        let mnemonic_words =
            words.get_words_from_index(&Mnemonic::generate_word_index_list(&mut entropy)?)?;

        Ok(Mnemonic {
            mnemonic_words: mnemonic_words,
            entropy: entropy,
        })
    }

    ///
    /// Get the mnemonic phrase
    ///
    pub fn get_phrase(&self) -> String {
        Mnemonic::get_phrase_from_words(&self.mnemonic_words)
    }

    ///
    /// Concatenate given words
    /// 
    fn get_phrase_from_words(words: &Vec<String>) -> String {
        words.join(" ")
    }

    ///
    /// Generate the list of index from entropy
    /// 
    fn generate_word_index_list(entropy: &mut Entropy) -> Result<Vec<u16>, BIP32Error> {
        let entropy_checksum = entropy.concat_with_checksum();
        let mut bit_reader = BitReader::new(entropy_checksum.as_ref());
        let mut words_index: Vec<u16> = vec![];

        //Now, we need to iterate into group of 11 bits (0 - 2047)
        for _i in 1..=(entropy_checksum.nb_bits() / BITS_LEN_ITERATION) {
            words_index.push(
                bit_reader
                    .read_u16(BITS_LEN_ITERATION as u8)
                    .map_err(|e| BIP32Error::BitReader(e.to_string()))?,
            );
        }

        Ok(words_index)
    }

    /// 
    /// The number of words that will be generate
    /// 
    pub fn mnemonic_size(&self) -> usize {
        (self.entropy.entropy.nb_bytes() + self.entropy.checksum_size()) / BITS_LEN_ITERATION
    }

    ///
    /// Borrow mnemonic words
    /// 
    pub fn get_words(&self) -> Vec<&String> {
        self.mnemonic_words.iter().collect()
    }

    /// 
    /// Mnemonic phrase must have at least 12 words, max 24 words and have to be divisible by 3
    /// 
    pub fn is_mnemonic_sentence_valid(sentence: String) -> bool {
        let length = sentence.split(' ').into_iter().count();
        length >= 12 && length <= 24 && length % 3 == 0
    }
}

///
/// Represent the seed of the mnemonic
/// 
pub struct Seed {
    val: Bytes,
}

impl Seed {
    ///
    /// Create a new seed
    /// 
    pub fn new(mnemonic_phrase: &String, passphrase: &Option<String>) -> Seed {
        let header = "mnemonic".to_owned();
        let passphrase_string = passphrase.to_owned().unwrap_or(String::from(""));
        let salt = [header.as_bytes(), passphrase_string.as_bytes()].concat();

        let seed = utils::pbkdf2_hash(mnemonic_phrase.as_bytes().to_vec(), salt);

        Seed {
            val: Bytes::new(seed),
        }
    }

    pub fn get_bytes(&self) -> &Bytes {
        &self.val
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.val)
    }
}

#[cfg(test)]
mod tests {
    use std::u8;
    use crate::{language::Language, mnemonic::EntropySize, NB_BITS_IN_BYTE};

    use super::{Entropy, Mnemonic};

    // Private function to create default entropy (only 0) from entropy size
    fn generate_default_entropy(nb_bytes: usize) -> Vec<u8> {
        (0..nb_bytes).map(|_| 0 as u8).collect::<Vec<u8>>()
    }

    #[test]
    fn mnemonic_word_index_from_default_entropy() {
        // Entropy default : 256 bits -> 24 words
        let words_index = Mnemonic::generate_word_index_list(
            &mut Entropy::from_bytes_vec(Entropy::default().entropy.into_vec()).unwrap(),
        )
        .unwrap();

        assert_eq!(words_index.len(), 24);
    }

    /// Test the words index number from entropy pass in parameter
    #[test]
    fn mnemonic_word_index_from_default_entropy_bytes() {
        let inputs = vec![
            //Entropy size         Nb words
            (EntropySize::Bits128, 12),
            (EntropySize::Bits160, 15),
            (EntropySize::Bits192, 18),
            (EntropySize::Bits224, 21),
            (EntropySize::Bits256, 24),
        ];
        for (entropy_size, nb_words_index) in inputs.into_iter() {
            //
            let words_index = Mnemonic::generate_word_index_list(
                &mut Entropy::from_bytes_vec(generate_default_entropy(entropy_size.nb_bytes()))
                    .unwrap(),
            )
            .unwrap();

            println!(
                "{} bytes Entropy generated a tab of {} index words = {:?}",
                entropy_size.nb_bytes(),
                nb_words_index,
                words_index
            );
            assert_eq!(words_index.len(), nb_words_index as usize);
        }
    }

    #[test]
    fn create_mnemonic_from_default_entropy_bytes() {
        let inputs = vec![
            //Entropy size         Nb words
            (EntropySize::Bits128, 4, 12),
            (EntropySize::Bits160, 5, 15),
            (EntropySize::Bits192, 6, 18),
            (EntropySize::Bits224, 7, 21),
            (EntropySize::Bits256, 8, 24),
        ];
        for (entropy_size, _checksum_bits_length, nb_words) in inputs.into_iter() {
            let mnemonic = Mnemonic::from_entropy(
                Entropy::from_bytes_vec(generate_default_entropy(entropy_size.nb_bytes())).unwrap(),
                Language::English,
            )
            .unwrap();

            assert_eq!(mnemonic.entropy.get_entropy_size(), entropy_size);
            assert_eq!(mnemonic.mnemonic_words.len(), nb_words);
        }
    }

    #[test]
    fn test_create_mnemonic_128() {
        // From bytes
        let mnemonic_from_bytes = Mnemonic::from_entropy(
            Entropy::from_bytes_vec(generate_default_entropy(128 / NB_BITS_IN_BYTE)).unwrap(),
            crate::language::Language::English,
        )
        .unwrap();
        assert_eq!(
            mnemonic_from_bytes.entropy.get_entropy_size(),
            Entropy::generate(EntropySize::Bits128).get_entropy_size()
        );
        assert_eq!(mnemonic_from_bytes.to_string(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");

        // From hexa
        let mnemonic_from_hexa = Mnemonic::from_entropy(
            Entropy::from_hex("00000000000000000000000000000000".to_owned()).unwrap(),
            crate::language::Language::English,
        )
        .unwrap();

        assert_eq!(mnemonic_from_hexa.to_string(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    }

    #[test]
    fn generate_random_mnemonic_and_check_if_num_words_is_valid() {
        // Entropy => 128 bits = 12 words
        assert_eq!(
            Mnemonic::create(EntropySize::Bits128, Language::English)
                .expect("Error when creating mnemonic from entropy size Bits128")
                .get_words()
                .len(),
            12
        );

        // Entropy => 128 bits = 15 words
        assert_eq!(
            Mnemonic::create(EntropySize::Bits160, Language::English)
                .expect("Error when creating mnemonic from entropy size Bits160")
                .get_words()
                .len(),
            15
        );

        // Entropy => 192 bits = 18 words
        assert_eq!(
            Mnemonic::create(EntropySize::Bits192, Language::English)
                .expect("Error when creating mnemonic from entropy size Bits192")
                .get_words()
                .len(),
            18
        );

        // Entropy => 224 bits = 21 words
        assert_eq!(
            Mnemonic::create(EntropySize::Bits224, Language::English)
                .expect("Error when creating mnemonic from entropy size Bits224")
                .get_words()
                .len(),
            21
        );

        // Entropy => 256 bits = 24 words
        assert_eq!(
            Mnemonic::create(EntropySize::Bits256, Language::English)
                .expect("Error when creating mnemonic from entropy size Bits256")
                .get_words()
                .len(),
            24
        );
    }

    #[test]
    fn generate_mnemonic() {
        let mnemonic_default_128 = Mnemonic::from_entropy(
            Entropy::from_bytes_vec(generate_default_entropy(128 / NB_BITS_IN_BYTE)).unwrap(),
            crate::language::Language::English,
        )
        .unwrap();

        assert_eq!( mnemonic_default_128.get_phrase(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_owned());
    }
}
