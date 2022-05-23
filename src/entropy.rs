use crate::{error::BIP32Error, language::WordsCount, utils, ENTROPY_MULTIPLE, NB_BITS_IN_BYTE};

///
/// The entropy bits number
///
#[derive(Debug, PartialEq)]
pub enum EntropySize {
    Bits128,
    Bits160,
    Bits192,
    Bits224,
    Bits256,
}

impl EntropySize {
    ///
    /// Get nb bits associated from entropy size
    ///
    pub fn nb_bits(&self) -> usize {
        match &self {
            EntropySize::Bits128 => 128,
            EntropySize::Bits160 => 160,
            EntropySize::Bits192 => 192,
            EntropySize::Bits224 => 224,
            EntropySize::Bits256 => 256,
        }
    }

    ///
    /// Get nb bits associated from entropy size
    ///
    pub fn nb_bytes(&self) -> usize {
        self.nb_bits() / NB_BITS_IN_BYTE
    }
}

///
/// Mapping between the mnemonic numbers count and the entropy size
///
impl From<WordsCount> for EntropySize {
    fn from(nb_words: WordsCount) -> Self {
        match nb_words {
            WordsCount::Words12 => EntropySize::Bits128,
            WordsCount::Words15 => EntropySize::Bits160,
            WordsCount::Words18 => EntropySize::Bits192,
            WordsCount::Words21 => EntropySize::Bits224,
            WordsCount::Words24 => EntropySize::Bits256,
        }
    }
}

///
/// Create entropy size from number
///
impl From<usize> for EntropySize {
    fn from(len: usize) -> Self {
        match len {
            128 => EntropySize::Bits128,
            160 => EntropySize::Bits160,
            192 => EntropySize::Bits192,
            224 => EntropySize::Bits224,
            _ => EntropySize::Bits256,
        }
    }
}

///
/// Get the entropy size from Entropy
///
impl From<Entropy> for EntropySize {
    fn from(ent: Entropy) -> Self {
        EntropySize::from(ent.entropy.val.len() * NB_BITS_IN_BYTE)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bytes {
    val: Vec<u8>,
}

impl Bytes {
    ///
    /// Create new bytes structure
    ///
    pub fn new(val: Vec<u8>) -> Bytes {
        Bytes::from(val)
    }

    pub fn as_vec(&self) -> &Vec<u8> {
        &self.val
    }

    pub fn into_vec(&self) -> Vec<u8> {
        self.val.clone()
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.val.as_ref()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.val)
    }

    pub fn nb_bytes(&self) -> usize {
        self.val.len()
    }

    pub fn nb_bits(&self) -> usize {
        self.val.len() * NB_BITS_IN_BYTE
    }

    pub fn sha256(&self) -> Bytes {
        Bytes::new(utils::sha256(&self.val))
    }

    pub fn take(&self, count: usize) -> Bytes {
        Bytes::new(self.val.clone().into_iter().take(count).collect())
    }

    ///
    /// Concat two bytes vector
    /// 
    pub fn concat(&self, other: &mut Bytes) -> Bytes {
        let mut res = self.val.clone();
        res.append(&mut other.val);
        Bytes::new(res)
    }

    ///
    /// Get bytes from hexadecimal
    /// 
    pub fn from_hex(hex: String) -> Result<Bytes, BIP32Error> {
        Ok(Bytes::new(
            hex::decode(hex).map_err(|e| BIP32Error::HexError(e.to_string()))?,
        ))
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.val.as_ref()
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(val: Vec<u8>) -> Self {
        Bytes { val }
    }
}

/// 
/// Represent the entropy the be able to build mnemonic
/// Entropy (ENT) representation
/// The allowed size of ENT is 128-256 bits and have to be a multiple of 32 bits
/// 
#[derive(Debug, Clone, PartialEq)]
pub struct Entropy {
    pub entropy: Bytes,
}

impl Entropy {
    /// 
    /// Create a new entropy from bytes
    /// 
    pub fn from_bytes_vec(entropy_bytes: Vec<u8>) -> Result<Entropy, BIP32Error> {
        Entropy::try_from(entropy_bytes)
    }

    /// 
    /// Create a new entropy from hex string
    /// 
    pub fn from_hex(hex: String) -> Result<Entropy, BIP32Error> {
        Ok(Entropy {
            entropy: Bytes::from_hex(hex)?,
        })
    }

    /// 
    /// Generate a random entropy from the specific EntropySize selected
    /// 
    pub fn generate(entropy_size: EntropySize) -> Entropy {
        Entropy::from(entropy_size)
    }

    ///
    /// Entropy to EntropySize enum
    /// 
    pub fn get_entropy_size(&self) -> EntropySize {
        self.clone().into()
    }

    /// 
    /// Calc checksum from entropy
    /// 
    pub fn checksum(&self) -> Bytes {
        self.entropy.sha256()
    }

    ///
    /// Get the checksum size (usually 1 byte)
    /// 
    pub fn checksum_size(&self) -> usize {
        self.checksum().nb_bytes() / ENTROPY_MULTIPLE
    }

    ///
    /// Concat current entropy with checksum
    /// 
    pub fn concat_with_checksum(&mut self) -> Bytes {
        self.entropy
            .concat(&mut self.checksum().take(self.checksum_size()))
    }
}

/// 
/// Try to create entropy from byte vector
/// 
impl TryFrom<Vec<u8>> for Entropy {
    type Error = BIP32Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() * NB_BITS_IN_BYTE < 128
            || value.len() * NB_BITS_IN_BYTE > 256
            || value.len() * NB_BITS_IN_BYTE % ENTROPY_MULTIPLE != 0
        {
            return Err(BIP32Error::InvalidEntropy);
        }

        Ok(Entropy {
            entropy: Bytes { val: value },
        })
    }
}

/// 
/// Create entropy from selected enum entropy size
/// 
impl From<EntropySize> for Entropy {
    fn from(entropy_size: EntropySize) -> Self {
        Entropy {
            entropy: Bytes::from(
                (0..entropy_size.nb_bytes())
                    .map(|_| rand::random::<u8>())
                    .collect::<Vec<u8>>(),
            ),
        }
    }
}

///
/// Setup a default entropy 
/// 
impl Default for Entropy {
    fn default() -> Self {
        Self {
            entropy: Bytes::new(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        entropy::{Entropy, EntropySize},
        error::BIP32Error,
        language::WordsCount,
        NB_BITS_IN_BYTE,
    };

    // Private function to create default entropy (only 0) from entropy size
    fn generate_default_entropy(nb_bytes: usize) -> Vec<u8> {
        (0..nb_bytes).map(|_| 0 as u8).collect::<Vec<u8>>()
    }

    ///
    /// Trying all posibilities of entropy manipulation
    ///
    #[test]
    fn entropy_length_mapping() {
        let default_128_entropy =
            Entropy::from_bytes_vec(generate_default_entropy(128 / NB_BITS_IN_BYTE)).unwrap();
        let default_160_entropy =
            Entropy::from_bytes_vec(generate_default_entropy(160 / NB_BITS_IN_BYTE)).unwrap();
        let default_192_entropy =
            Entropy::from_bytes_vec(generate_default_entropy(192 / NB_BITS_IN_BYTE)).unwrap();
        let default_224_entropy =
            Entropy::from_bytes_vec(generate_default_entropy(224 / NB_BITS_IN_BYTE)).unwrap();
        let default_256_entropy =
            Entropy::from_bytes_vec(generate_default_entropy(256 / NB_BITS_IN_BYTE)).unwrap();

        assert_eq!(EntropySize::from(128), EntropySize::Bits128);
        assert_eq!(EntropySize::from(160), EntropySize::Bits160);
        assert_eq!(EntropySize::from(192), EntropySize::Bits192);
        assert_eq!(EntropySize::from(224), EntropySize::Bits224);
        assert_eq!(EntropySize::from(256), EntropySize::Bits256);

        assert_eq!(
            default_128_entropy.entropy.as_vec(),
            &vec![0 as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            default_160_entropy.entropy.as_vec(),
            &vec![0 as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            default_192_entropy.entropy.as_vec(),
            &vec![0 as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            default_224_entropy.entropy.as_vec(),
            &vec![
                0 as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0
            ]
        );
        assert_eq!(
            default_256_entropy.entropy.as_vec(),
            &vec![
                0 as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0
            ]
        );

        assert_eq!(EntropySize::from(default_128_entropy), EntropySize::Bits128);
        assert_eq!(EntropySize::from(default_160_entropy), EntropySize::Bits160);
        assert_eq!(EntropySize::from(default_192_entropy), EntropySize::Bits192);
        assert_eq!(EntropySize::from(default_224_entropy), EntropySize::Bits224);
        assert_eq!(EntropySize::from(default_256_entropy), EntropySize::Bits256);

        assert_eq!(EntropySize::from(WordsCount::Words12), EntropySize::Bits128);
        assert_eq!(EntropySize::from(WordsCount::Words15), EntropySize::Bits160);
        assert_eq!(EntropySize::from(WordsCount::Words18), EntropySize::Bits192);
        assert_eq!(EntropySize::from(WordsCount::Words21), EntropySize::Bits224);
        assert_eq!(EntropySize::from(WordsCount::Words24), EntropySize::Bits256);
    }

    /// 
    /// Create entropy from hexadecimal
    /// 
    #[test]
    fn entropy_from_hex() {
        let entropy = Entropy::from_hex("00000000000000000000000000000000".to_owned()).unwrap();
        assert_eq!(
            entropy.entropy.val,
            vec![0 as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(entropy.get_entropy_size(), EntropySize::Bits128);

        let entropy = Entropy::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        )
        .unwrap();
        assert_eq!(entropy.get_entropy_size(), EntropySize::Bits256);
    }

    /// 
    /// Entropy bits len < 128 or > 256 or not modulo 32, should throw an error
    /// 
    #[test]
    fn entropy_creation_fail() {
        // Entropy < 128
        assert_eq!(
            Entropy::try_from(generate_default_entropy(120 / NB_BITS_IN_BYTE)),
            Err(BIP32Error::InvalidEntropy)
        );
        assert_eq!(
            Entropy::from_bytes_vec(generate_default_entropy(120 / NB_BITS_IN_BYTE)),
            Err(BIP32Error::InvalidEntropy)
        );

        // Entropy > 256
        assert_eq!(
            Entropy::try_from(generate_default_entropy(288 / NB_BITS_IN_BYTE)),
            Err(BIP32Error::InvalidEntropy)
        );
        assert_eq!(
            Entropy::from_bytes_vec(generate_default_entropy(288 / NB_BITS_IN_BYTE)),
            Err(BIP32Error::InvalidEntropy)
        );

        // Entropy not % 32
        assert_eq!(
            Entropy::try_from(generate_default_entropy(140 / NB_BITS_IN_BYTE)),
            Err(BIP32Error::InvalidEntropy)
        );
        assert_eq!(
            Entropy::from_bytes_vec(generate_default_entropy(140 / NB_BITS_IN_BYTE)),
            Err(BIP32Error::InvalidEntropy)
        );
    }

    /// 
    /// Generate entropy from entropy size
    /// 
    #[test]
    fn generate_entropy_should_succeed() {
        assert_eq!(
            Entropy::generate(super::EntropySize::Bits128)
                .entropy
                .nb_bytes(),
            super::EntropySize::Bits128.nb_bytes()
        );
        assert_eq!(
            Entropy::generate(super::EntropySize::Bits160)
                .entropy
                .nb_bytes(),
            super::EntropySize::Bits160.nb_bytes()
        );
        assert_eq!(
            Entropy::generate(super::EntropySize::Bits192)
                .entropy
                .nb_bytes(),
            super::EntropySize::Bits192.nb_bytes()
        );
        assert_eq!(
            Entropy::generate(super::EntropySize::Bits224)
                .entropy
                .nb_bytes(),
            super::EntropySize::Bits224.nb_bytes()
        );
        assert_eq!(
            Entropy::generate(super::EntropySize::Bits256)
                .entropy
                .nb_bytes(),
            super::EntropySize::Bits256.nb_bytes()
        );
    }

    /// 
    /// Create entropy from default traits (256 bits, only 0) and calc checksum
    /// 
    #[test]
    fn create_entropy_from_default_and_calc_checksum() {
        // Default entropy (all bytes = 0)
        let mut entropy = Entropy::from_bytes_vec(Entropy::default().entropy.val).unwrap();
        let checksum = entropy.concat_with_checksum();

        assert_eq!(entropy.entropy.nb_bits(), 256);
        assert_eq!(checksum.nb_bits(), 264);
    }
}
