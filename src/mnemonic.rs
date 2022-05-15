use std::{fmt::Display, u8};

use crate::{
    entropy::{Entropy, EntropySize},
    error::BIP32Error,
    language::{Language, Words},
    BITS_LEN_ITERATION,
};
use bitreader::BitReader;

/// Nb bits in Byte = 8
/// entropy: between 16 Bytes and 32 Bytes
/// entropy : list of byte / 128-256 bits / between 16-32 Bytes / entropy multiple : 32
/// passphrase: list of byte
/// Language : enum

/// mnemonic to entropy
/// seed from entropy

/// Entropy (ENT) representation
/// The allowed size of ENT is 128-256 bits and have to be a multiple of 32 bits

pub struct Mnemonic {
    mnemonic_words: Vec<String>,
    pub entropy: Entropy,
    pub passphrase: String,
}

impl Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mnemonic_words.join(" "))
    }
}

impl Mnemonic {
    /// Create a mnemonic from the given entropy size
    pub fn create(
        entropy_size: EntropySize,
        passphrase: Option<String>,
        lang: Language,
    ) -> Result<Mnemonic, BIP32Error> {
        Mnemonic::from_entropy(Entropy::generate(entropy_size), passphrase, lang)
    }

    pub fn from_entropy(
        mut entropy: Entropy,
        passphrase: Option<String>,
        lang: Language,
    ) -> Result<Mnemonic, BIP32Error> {
        let words = Words::load(lang)?;
        let mnemonic_words =
            words.get_words_from_index(&Mnemonic::generate_word_index_list(&mut entropy)?)?;
        // println!("4 >> {:?}", mnemonic_words);

        Ok(Mnemonic {
            mnemonic_words: mnemonic_words,
            passphrase: String::from(""),
            entropy: entropy,
        })
    }

    fn generate_word_index_list(entropy: &mut Entropy) -> Result<Vec<u16>, BIP32Error> {
        let entropy_checksum = entropy.concat_with_checksum();
        let mut bit_reader = BitReader::new(entropy_checksum.val.as_slice());
        let mut words_index: Vec<u16> = vec![];

        //Now, we need to iterate into group of 11 bits (0 - 2047)
        for i in 1..=(entropy_checksum.nb_bits() / BITS_LEN_ITERATION) {
            words_index.push(
                bit_reader
                    .read_u16(BITS_LEN_ITERATION as u8)
                    .map_err(|e| BIP32Error::BitReader(e.to_string()))?,
            );
        }

        Ok(words_index)
    }

    /// The number of words that will be generate
    pub fn mnemonic_size(&self) -> usize {
        (self.entropy.entropy.nb_bytes() + self.entropy.checksum_size()) / BITS_LEN_ITERATION
    }

    // pub fn sha256(bytes: &Vec<u8>) -> Vec<u8> {
    //     let mut hasher = Sha256::new();
    //     hasher.update(bytes);
    //     hasher.finalize().to_vec()
    // }

    pub fn get_words(&self) -> Vec<&String> {
        self.mnemonic_words.iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use std::u8;

    use crate::{
        error::BIP32Error, language::Language, mnemonic::EntropySize, utils, NB_BITS_IN_BYTE,
    };

    use super::{Entropy, Mnemonic, BITS_LEN_ITERATION};

    // Private function to create default entropy (only 0) from entropy size
    fn generate_default_entropy(nb_bytes: usize) -> Vec<u8> {
        (0..nb_bytes).map(|_| 0 as u8).collect::<Vec<u8>>()
    }

    #[test]
    fn mnemonic_word_index_from_default_entropy() {
        // Entropy default : 256 bits -> 24 words
        let words_index = Mnemonic::generate_word_index_list(
            &mut Entropy::from_bytes_vec(Entropy::default().entropy.val).unwrap(),
        )
        .unwrap();

        println!("{:?}", words_index);
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
        for (entropy_size, checksum_bits_length, nb_words) in inputs.into_iter() {
            let mnemonic = Mnemonic::from_entropy(
                Entropy::from_bytes_vec(generate_default_entropy(entropy_size.nb_bytes())).unwrap(),
                None,
                Language::English,
            )
            .unwrap();

            // println!("{}", entropy_size.nb_bytes());

            assert_eq!(mnemonic.entropy.get_entropy_size(), entropy_size);
            //assert_eq!(mnemonic.entropy.checksum().nb_bits() / ENTROPY_MULTIPLE, checksum_bits_length);
            assert_eq!(mnemonic.mnemonic_words.len(), nb_words);
            // println!("ZOB >> {:?}", mnemonic.get_words());
            println!("{:?} >> {}", entropy_size, mnemonic);

            assert!(true);
            //assert_eq!(words_index.len(), args.1);
        }
    }

    #[test]
    fn test_create_mnemonic_128() {
        // From bytes
        let mnemonic_from_bytes = Mnemonic::from_entropy(
            Entropy::from_bytes_vec(generate_default_entropy(128 / NB_BITS_IN_BYTE)).unwrap(),
            None,
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
            None,
            crate::language::Language::English,
        )
        .unwrap();

        assert_eq!(mnemonic_from_hexa.to_string(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    }

    #[test]
    fn create_mnemonic_from_vectors() {
        // Vector from https://github.com/trezor/python-mnemonic/blob/master/vectors.json
        let list = vec![
            (
                "00000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
            ),
            (
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
                "xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq"
            ),
            (
                "80808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
                "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
                "xprv9s21ZrQH143K2shfP28KM3nr5Ap1SXjz8gc2rAqqMEynmjt6o1qboCDpxckqXavCwdnYds6yBHZGKHv7ef2eTXy461PXUjBFQg6PrwY4Gzq"
            ),
            (
                "ffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
                "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
                "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd"
            ),
            (
                "000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
                "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
                "xprv9s21ZrQH143K3mEDrypcZ2usWqFgzKB6jBBx9B6GfC7fu26X6hPRzVjzkqkPvDqp6g5eypdk6cyhGnBngbjeHTe4LsuLG1cCmKJka5SMkmU"
            ),
            (
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
                "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
                "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VT4gz4wt5RM23pkaQLnvBh7"
            ),
            (
                "808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
                "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
                "xprv9s21ZrQH143K3VPCbxbUtpkh9pRG371UCLDz3BjceqP1jz7XZsQ5EnNkYAEkfeZp62cDNj13ZTEVG1TEro9sZ9grfRmcYWLBhCocViKEJae"
            ),
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
                "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
                "xprv9s21ZrQH143K36Ao5jHRVhFGDbLP6FCx8BEEmpru77ef3bmA928BxsqvVM27WnvvyfWywiFN8K6yToqMaGYfzS6Db1EHAXT5TuyCLBXUfdm"
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
                "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
                "xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM"
            ),
            (
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
                "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
                "xprv9s21ZrQH143K3Y1sd2XVu9wtqxJRvybCfAetjUrMMco6r3v9qZTBeXiBZkS8JxWbcGJZyio8TrZtm6pkbzG8SYt1sxwNLh3Wx7to5pgiVFU"
            ),
            (
                "8080808080808080808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
                "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
                "xprv9s21ZrQH143K3CSnQNYC3MqAAqHwxeTLhDbhF43A4ss4ciWNmCY9zQGvAKUSqVUf2vPHBTSE1rB2pg4avopqSiLVzXEU8KziNnVPauTqLRo"
            ),
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
                "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
                "xprv9s21ZrQH143K2WFF16X85T2QCpndrGwx6GueB72Zf3AHwHJaknRXNF37ZmDrtHrrLSHvbuRejXcnYxoZKvRquTPyp2JiNG3XcjQyzSEgqCB"
            ),
            (
                "9e885d952ad362caeb4efe34a8e91bd2",
                "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
                "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
                "xprv9s21ZrQH143K2oZ9stBYpoaZ2ktHj7jLz7iMqpgg1En8kKFTXJHsjxry1JbKH19YrDTicVwKPehFKTbmaxgVEc5TpHdS1aYhB2s9aFJBeJH"
            ),
            (
                "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
                "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
                "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
                "xprv9s21ZrQH143K3uT8eQowUjsxrmsA9YUuQQK1RLqFufzybxD6DH6gPY7NjJ5G3EPHjsWDrs9iivSbmvjc9DQJbJGatfa9pv4MZ3wjr8qWPAK"
            ),
            (
                "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
                "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
                "xprv9s21ZrQH143K2XTAhys3pMNcGn261Fi5Ta2Pw8PwaVPhg3D8DWkzWQwjTJfskj8ofb81i9NP2cUNKxwjueJHHMQAnxtivTA75uUFqPFeWzk"
            ),
            (
                "c0ba5a8e914111210f2bd131f3d5e08d",
                "scheme spot photo card baby mountain device kick cradle pact join borrow",
                "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
                "xprv9s21ZrQH143K3FperxDp8vFsFycKCRcJGAFmcV7umQmcnMZaLtZRt13QJDsoS5F6oYT6BB4sS6zmTmyQAEkJKxJ7yByDNtRe5asP2jFGhT6"
            ),
            (
                "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
                "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
                "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
                "xprv9s21ZrQH143K3R1SfVZZLtVbXEB9ryVxmVtVMsMwmEyEvgXN6Q84LKkLRmf4ST6QrLeBm3jQsb9gx1uo23TS7vo3vAkZGZz71uuLCcywUkt"
            ),
            (
                "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
                "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
                "xprv9s21ZrQH143K2WNnKmssvZYM96VAr47iHUQUTUyUXH3sAGNjhJANddnhw3i3y3pBbRAVk5M5qUGFr4rHbEWwXgX4qrvrceifCYQJbbFDems"
            ),
            (
                "23db8160a31d3e0dca3688ed941adbf3",
                "cat swing flag economy stadium alone churn speed unique patch report train",
                "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
                "xprv9s21ZrQH143K4G28omGMogEoYgDQuigBo8AFHAGDaJdqQ99QKMQ5J6fYTMfANTJy6xBmhvsNZ1CJzRZ64PWbnTFUn6CDV2FxoMDLXdk95DQ"
            ),
            (
                "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
                "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
                "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
                "xprv9s21ZrQH143K3wtsvY8L2aZyxkiWULZH4vyQE5XkHTXkmx8gHo6RUEfH3Jyr6NwkJhvano7Xb2o6UqFKWHVo5scE31SGDCAUsgVhiUuUDyh"
            ),
            (
                "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
                "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
                "xprv9s21ZrQH143K3rEfqSM4QZRVmiMuSWY9wugscmaCjYja3SbUD3KPEB1a7QXJoajyR2T1SiXU7rFVRXMV9XdYVSZe7JoUXdP4SRHTxsT1nzm"
            ),
            (
                "f30f8c1da665478f49b001d94c5fc452",
                "vessel ladder alter error federal sibling chat ability sun glass valve picture",
                "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
                "xprv9s21ZrQH143K2QWV9Wn8Vvs6jbqfF1YbTCdURQW9dLFKDovpKaKrqS3SEWsXCu6ZNky9PSAENg6c9AQYHcg4PjopRGGKmdD313ZHszymnps"
            ),
            (
                "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
                "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
                "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
                "xprv9s21ZrQH143K4aERa2bq7559eMCCEs2QmmqVjUuzfy5eAeDX4mqZffkYwpzGQRE2YEEeLVRoH4CSHxianrFaVnMN2RYaPUZJhJx8S5j6puX"
            ),
            (
                "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
                "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
                "xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS"
            ),
        ];

        for (hexa, mnemonic_phrase, _, _) in list.into_iter() {
            assert_eq!(
                Mnemonic::from_entropy(
                    Entropy::from_hex(hexa.to_owned()).unwrap(),
                    None,
                    crate::language::Language::English,
                )
                .unwrap()
                .to_string(),
                mnemonic_phrase
            )
        }
    }

    #[test]
    fn generate_random_mnemonic_and_check_if_valid() {
        // Entropy => 128 bits = 12 words
        assert_eq!(
            Mnemonic::create(EntropySize::Bits128, None, Language::English)
                .expect("Error when creating mnemonic from entropy size Bits128")
                .get_words()
                .len(),
            12
        );

        // Entropy => 128 bits = 12 words
        assert_eq!(
            Mnemonic::create(EntropySize::Bits160, None, Language::English)
                .expect("Error when creating mnemonic from entropy size Bits160")
                .get_words()
                .len(),
            15
        );

        // Entropy => 192 bits = 12 words
        assert_eq!(
            Mnemonic::create(EntropySize::Bits192, None, Language::English)
                .expect("Error when creating mnemonic from entropy size Bits192")
                .get_words()
                .len(),
            18
        );

        // Entropy => 224 bits = 12 words
        assert_eq!(
            Mnemonic::create(EntropySize::Bits224, None, Language::English)
                .expect("Error when creating mnemonic from entropy size Bits224")
                .get_words()
                .len(),
            21
        );

        // Entropy => 256 bits = 12 words
        assert_eq!(
            Mnemonic::create(EntropySize::Bits256, None, Language::English)
                .expect("Error when creating mnemonic from entropy size Bits256")
                .get_words()
                .len(),
            24
        );
    }
}
