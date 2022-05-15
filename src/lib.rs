///
/// Bitcoin Improvement Proposal (BIP 39)
/// It's a 12 / 24 recovery seed phrase, a group of easy to remember words, which serve as recover your wallet
/// The words are choosen in a specific list of 2048 words. Each word of this list has
/// Explanation from :
///     https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md
///     https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
///     https://www.blockplate.com/pages/bip-39-wordlist
///     https://www.blockplate.com/blogs/blockplate/list-of-bip39-wallets-mnemonic-seed

mod entropy;
mod utils;
mod mnemonic;
mod error;
mod language;

/* Config */
const NB_BITS_IN_BYTE: usize = 8;
const ENTROPY_MULTIPLE: usize = 32;
const BITS_LEN_ITERATION: usize = 11;