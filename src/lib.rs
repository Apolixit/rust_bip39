use crate::entropy::Entropy;
use crate::error::BIP32Error;
use crate::language::Language;
use crate::language::WordsCount;
use mnemonic::Mnemonic;
use mnemonic::Seed;

///
/// Bitcoin Improvement Proposal (BIP 39)
/// It's a 12 / 24 recovery seed phrase, a group of easy to remember words, which serve as recover your wallet
/// The words are choosen in a specific list of 2048 words. Each word of this list has
/// Explanation from :
///     https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md
///     https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
///     https://www.blockplate.com/pages/bip-39-wordlist
///     https://www.blockplate.com/blogs/blockplate/list-of-bip39-wallets-mnemonic-seed

pub mod entropy;
pub mod error;
pub mod language;
pub mod mnemonic;
pub mod utils;

/* Config */
const NB_BITS_IN_BYTE: usize = 8;
const ENTROPY_MULTIPLE: usize = 32;
const BITS_LEN_ITERATION: usize = 11;

/// Generate a new Mnemonic from given words count, with optional Passphrase and mnemonic words language.
pub fn generate_mnemonic(
    nb_words: WordsCount,
    lang: Language,
) -> Result<Mnemonic, BIP32Error> {
    Ok(Mnemonic::create(nb_words.into(), lang)?)
}

/// Generate a new mnemonic from a given entropy
pub fn generate_mnemonic_from_entropy(
    entropy: Entropy,
    lang: Language,
) -> Result<Mnemonic, BIP32Error> {
    Ok(Mnemonic::from_entropy(entropy, lang)?)
}

/// Get seed from current mnemonic phrase and passphrase
pub fn get_seed_from_phrase(
    mnemonic_phrase: String,
    passphrase: Option<String>
) -> Seed {
    Seed::new(&mnemonic_phrase, &passphrase)
}