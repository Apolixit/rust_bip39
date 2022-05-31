use std::{fs, path::Path};
use crate::{error::BIP32Error, utils};

///
/// Number of words in mnemonic
///
#[derive(Debug, PartialEq)]
pub enum WordsCount {
    Words12,
    Words15,
    Words18,
    Words21,
    Words24,
}

///
/// Create words count from number
///
impl From<usize> for WordsCount {
    fn from(len: usize) -> Self {
        match len {
            12 => WordsCount::Words12,
            15 => WordsCount::Words15,
            18 => WordsCount::Words18,
            21 => WordsCount::Words21,
            _ => WordsCount::Words24,
        }
    }
}

///
/// The mnemonic lang
///
pub enum Language {
    /// English words, bind to "english.txt"
    English,
    /// French words, bind to "french.txt"
    French,
    /// Italian words, bind to "italian.txt"
    Italian,
    /// Japanese words, bind to "japanese.txt"
    Japanese,
    /// Korean words, bind to "korean.txt"
    Korean,
    /// Portugese words, bind to "portugese.txt"
    Portugese,
    /// Spanish words, bind to "spanish.txt"
    Spanish,
    /// Czech republic words, bind to "czech.txt"
    Czech,
}

///
/// The 2048 words associate to the current language
///
pub struct Words {
    list: Vec<String>,
    language: Language,
}

impl Words {
    ///
    /// Load all words from lang file
    ///
    pub fn load(language: Language) -> Result<Words, BIP32Error> {
        let language_content = Words::read_file(&language)?;
        let words = Words::read_words(language_content)?;

        Ok(Words {
            list: words,
            language,
        })
    }

    ///
    /// Return the current language
    /// 
    pub fn current_language(&self) -> &Language {
        &self.language
    }

    ///
    /// Open and read the file associate to current language
    ///
    fn read_file(language: &Language) -> Result<String, BIP32Error> {
        let read_file = |path| {
            fs::read_to_string(Path::new(path)).map_err(|e| BIP32Error::ReadFile(e.to_string()))
        };

        Ok(match language {
            Language::English => read_file("src/words/english.txt")?,
            Language::French => read_file("src/words/french.txt")?,
            Language::Italian => read_file("src/words/italian.txt")?,
            Language::Japanese => read_file("src/words/japanese.txt")?,
            Language::Korean => read_file("src/words/korean.txt")?,
            Language::Portugese => read_file("src/words/portugese.txt")?,
            Language::Spanish => read_file("src/words/spanish.txt")?,
            Language::Czech => read_file("src/words/czech.txt")?,
        })
    }

    ///
    /// Read words and split them to vector
    ///
    fn read_words(content: String) -> Result<Vec<String>, BIP32Error> {
        let words: Vec<String> = content
            .split('\n')
            .into_iter()
            .map(|x| utils::to_utf8_nfkd(x.trim().to_owned()))
            .collect();

        if words.len() != 2048 {
            return Err(BIP32Error::InvalidWordsCount(words.len()));
        }

        Ok(words)
    }

    ///
    /// Get associated words from list of index
    ///
    pub fn get_words_from_index(&self, words_index: &Vec<u16>) -> Result<Vec<String>, BIP32Error> {
        let mut words: Vec<String> = vec![];

        for i in words_index {
            words.push(
                self.list
                    .clone()
                    .into_iter()
                    .enumerate()
                    .find(|(index_word, _)| *i == *index_word as u16)
                    .map(|f| f.1)
                    .ok_or(BIP32Error::WordNotFound(*i))?,
            );
        }

        // We need to have the same number of words than words index list
        if words.len() != words_index.len() {
            return Err(BIP32Error::InvalidWordsCount(words.len()));
        }

        Ok(words)
    }

    ///
    /// Does the current language have this word in the dictionnary ?
    ///
    pub fn contain_word(&self, word: String) -> bool {
        self.list.iter().any(|w| w == &word)
    }

    ///
    /// Generate mnemonic phrase from current words list
    ///
    pub fn get_phrase(&self) -> String {
        Words::get_phrase_from_words(&self.list)
    }

    ///
    /// Aggregate the list of string to build a string
    ///
    pub fn get_phrase_from_words(words: &Vec<String>) -> String {
        words.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use crate::error::BIP32Error;

    use super::{Language, Words};

    fn all_language() -> Vec<Language> {
        vec![Language::English, Language::French]
    }

    ///
    /// Check if the file associated to the current lang is not empty
    ///
    #[test]
    fn test_read_file_should_succeed() {
        for lang in all_language().iter() {
            let file_content = Words::read_file(&lang).unwrap();
            assert!(!file_content.is_empty());
        }
    }

    ///
    /// Read the 2048 words associated to current lang
    ///
    #[test]
    fn test_split_words_should_succeed() {
        for lang in all_language().iter() {
            let file_content = Words::read_file(lang).unwrap();
            let words = Words::read_words(file_content).unwrap();
            assert_eq!(words.len(), 2048);
        }
    }

    ///
    /// Split words from a bad parameter (empty string)
    ///
    #[test]
    fn test_split_words_from_empty_string_should_err() {
        // Expected "InvalidWordsCount(1)" because split an empty string result in a 1 lenght vec
        let expected_error = Err(BIP32Error::InvalidWordsCount(1));
        assert_eq!(Words::read_words(String::from("")), expected_error);
    }

    ///
    /// Get words from the selected word index
    ///
    #[test]
    fn test_get_words_from_index() {
        let words_index = vec![0, 2, 4, 6, 8, 10];
        let words = Words::load(Language::English).unwrap();

        let selected_words = words.get_words_from_index(&words_index).unwrap();

        assert_eq!(selected_words.len(), words_index.len());
        assert_eq!(selected_words[0], "abandon");
        assert_eq!(selected_words[1], "able");
        assert_eq!(selected_words.last().unwrap(), "access");
    }

    ///
    /// Check if we have no trouble of getting multiple duplicate same word
    ///
    #[test]
    fn test_get_words_from_index_with_duplicate() {
        let words_index = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 102,
        ];
        let words = Words::load(Language::English).unwrap();

        let selected_words = words.get_words_from_index(&words_index).unwrap();

        assert_eq!(selected_words.len(), words_index.len());
    }

    ///
    /// Basic words concatenation
    ///
    #[test]
    fn test_build_sentence() {
        assert_eq!(
            Words::get_phrase_from_words(&vec![
                "Hi".to_owned(),
                "im".to_owned(),
                "gozu".to_owned()
            ]),
            String::from("Hi im gozu")
        );
    }
}
