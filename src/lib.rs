///
/// Bitcoin Improvement Proposal (BIP 39)
/// It's a 12 / 24 recovery seed phrase, a group of easy to remember words, which serve as recover your wallet
/// The words are choosen in a specific list of 2048 words. Each word of this list has
/// Explanation from :
///     <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>
///     <https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md>
///     <https://github.com/bip32JP/bip32JP.github.io/blob/master/test_JP_BIP39.json>
///     <https://www.blockplate.com/pages/bip-39-wordlist>
///     <https://www.blockplate.com/blogs/blockplate/list-of-bip39-wallets-mnemonic-seed>
pub mod entropy;
pub mod error;
pub mod language;
pub mod mnemonic;
pub mod utils;

pub use mnemonic::Mnemonic;
pub use mnemonic::Seed;
pub use language::WordsCount;
pub use language::Language;
pub use entropy::Entropy;
pub use error::BIP32Error;

/* Config */
const NB_BITS_IN_BYTE: usize = 8;
const ENTROPY_MULTIPLE: usize = 32;
const BITS_LEN_ITERATION: usize = 11;

/// Generate a new Mnemonic from given words count, with optional Passphrase and mnemonic words language.
/// # Example
/// ```
/// use bip39::{WordsCount, Language};
/// let mnemonic = bip39::generate_mnemonic(WordsCount::Words24, Language::English);
/// match mnemonic {
///     Ok(ok_mnemonic) => {
///         println!("{}", ok_mnemonic.to_string());
///         assert_eq!(ok_mnemonic.get_words().len(), 24);
///     },
///     Err(e) => {
///         println!("Error : {}", e.message())
///     }
/// }
/// ```
pub fn generate_mnemonic(nb_words: WordsCount, lang: Language) -> Result<Mnemonic, BIP32Error> {
    Ok(Mnemonic::create(nb_words.into(), lang)?)
}

/// Generate a new Mnemonic from a given entropy
/// # Example
/// ```
/// use bip39::{Entropy, Language};
/// let mnemonic = bip39::generate_mnemonic_from_entropy(
///     Entropy::from_hex("00000000000000000000000000000000".to_owned()).unwrap(),
///     Language::English
/// ).unwrap();
/// assert_eq!(mnemonic.get_words().len(), 12);
/// ```
pub fn generate_mnemonic_from_entropy(
    entropy: Entropy,
    lang: Language,
) -> Result<Mnemonic, BIP32Error> {
    Ok(Mnemonic::from_entropy(entropy, lang)?)
}

/// Get seed from current Mnemonic phrase and passphrase
/// For more information / example, see "tests/bip39.rs"
/// # Example
/// ```
/// let seed = bip39::get_seed_from_phrase(
///     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_owned(),
///     Some("TREZOR".to_owned())
/// );
/// assert_eq!(seed.to_hex(), "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
/// ```
pub fn get_seed_from_phrase(mnemonic_phrase: String, passphrase: Option<String>) -> Seed {
    Seed::new(&mnemonic_phrase, &passphrase)
}
