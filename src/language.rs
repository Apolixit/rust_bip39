use std::{env, fs, path::Path};

use crate::error::BIP32Error;

pub enum Language {
    /// English words, bind to "english.txt"
    English,

    /// English words, bind to "french.txt"
    French,
}

pub struct Words {
    list: Vec<String>,
    language: Language,
}

impl Words {
    pub fn load(language: Language) -> Result<Words, BIP32Error> {
        let language_content = Words::read_file(&language)?;
        let words = Words::read_words(language_content)?;

        Ok(Words {
            list: words,
            language,
        })
    }

    // pub fn get_all_words(&self) -> Vec<String> {
    //     self.list
    // }

    /// Open and read the file associate to current language
    fn read_file(language: &Language) -> Result<String, BIP32Error> {
        let read_file =
            |path| fs::read_to_string(Path::new(path)).map_err(|e| BIP32Error::ReadFile(e.to_string()));

        Ok(match language {
            Language::English => read_file("src/words/english.txt")?,
            Language::French => read_file("src/words/french.txt")?,
        })
    }

    /// Read words and split them to vec
    fn read_words(content: String) -> Result<Vec<String>, BIP32Error> {
        let words: Vec<String> = content
            .split('\n')
            .into_iter()
            .map(|x| String::from(x.trim()))
            .collect();

        if words.len() != 2048 {
            return Err(BIP32Error::InvalidWordsCount(words.len()));
        }

        Ok(words)
    }

    pub fn get_words_from_index(&self, index: &Vec<u16>) -> Result<Vec<String>, BIP32Error> {
        let mut words: Vec<String> = vec![];

        for i in index {
            words.push(self
            .list
            .clone()
            .into_iter()
            .enumerate()
            .find(|(index_word, _)| *i == *index_word as u16)
            .map(|f| f.1)
            .ok_or(BIP32Error::WordNotFound(*i))?);
        }

        if words.len() != index.len() {
            return Err(BIP32Error::InvalidWordsCount(words.len()));
        }

        Ok(words)
    }
}

#[cfg(test)]
mod tests {
    use crate::error::BIP32Error;

    use super::{Language, Words};

    fn all_language() -> Vec<Language> { vec![Language::English, Language::French] }

    /// Check if the file associeted to the current lang is not empty
    #[test]
    fn test_read_file_should_succeed() {
        for lang in all_language().iter() {
            let file_content = Words::read_file(&lang).unwrap();
            assert!(!file_content.is_empty());
        }
    }

    /// Read the 2048 words associated to current lang
    #[test]
    fn test_split_words_should_succeed() {
        for lang in all_language().iter() {
            let file_content = Words::read_file(lang).unwrap();
            let words = Words::read_words(file_content).unwrap();
            assert_eq!(words.len(), 2048);
        }
    }

    /// Split words from a bad parameter (empty string)
    #[test]
    fn test_split_words_from_empty_string_should_err() {
        // Expected "InvalidWordsCount(1)" because split an empty string result in a 1 lenght vec
        let expected_error = Err(BIP32Error::InvalidWordsCount(1));
        assert_eq!(Words::read_words(String::from("")), expected_error);
    }


    #[test]
    fn test_get_words_from_index() {
        let words_index = vec![0, 2, 4, 6, 8, 10];
        let words = Words::load(Language::English).unwrap();

        let selected_words = words.get_words_from_index(&words_index).unwrap();

        assert_eq!(selected_words.len(), words_index.len());
        assert_eq!(selected_words.first().unwrap(), "abandon");
        assert_eq!(selected_words[1], "able");
        assert_eq!(selected_words.last().unwrap(), "access");
    }

    #[test]
    fn test_get_words_from_index_with_duplicate() {
        let words_index = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 102];
        let words = Words::load(Language::English).unwrap();

        let selected_words = words.get_words_from_index(&words_index).unwrap();

        assert_eq!(selected_words.len(), words_index.len());
    }
}
