use bip39::entropy::{Entropy};
use bip39::{generate_mnemonic, WordsCount, utils};
use bip39::language::Language;
use bip39::mnemonic::{Mnemonic, Seed};

#[test]
fn create_mnemonic_from_all_language() {
    // Vector from https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    let list = vec![
        (
            "00000000000000000000000000000000",
            vec![
                (Language::English, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
                (Language::French, "abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abeille"),
                (Language::Italian, "abaco abaco abaco abaco abaco abaco abaco abaco abaco abaco abaco abete"),
                (Language::Japanese, "あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あおぞら"),
                (Language::Korean, "가격 가격 가격 가격 가격 가격 가격 가격 가격 가격 가격 가능"),
                (Language::Portugese, "abacate abacate abacate abacate abacate abacate abacate abacate abacate abacate abacate abater"),
                (Language::Spanish, "ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco abierto"),
                (Language::Czech, "abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace agrese"),
            ],
        )
    ];

    for (hexa, langs) in list.into_iter() {
        for (lang, mnemonic_phrase) in langs.into_iter() {
            let current_mnemonic = Mnemonic::from_entropy(
                Entropy::from_hex(hexa.to_owned()).unwrap(),
                lang,
            )
            .unwrap();
    
            assert_eq!(mnemonic_phrase, current_mnemonic.to_string());
        }
        
    }
}

#[test]
fn generate_new_mnemonic() {
    assert_eq!(generate_mnemonic(bip39::language::WordsCount::Words24, Language::English).unwrap().get_words().len(), 24);
    assert_eq!(generate_mnemonic(bip39::language::WordsCount::Words21, Language::English).unwrap().get_words().len(), 21);
    assert_eq!(generate_mnemonic(bip39::language::WordsCount::Words18, Language::English).unwrap().get_words().len(), 18);
    assert_eq!(generate_mnemonic(bip39::language::WordsCount::Words15, Language::English).unwrap().get_words().len(), 15);
    assert_eq!(generate_mnemonic(bip39::language::WordsCount::Words12, Language::English).unwrap().get_words().len(), 12);
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

    for (entropy_hexa, mnemonic_phrase, seed_hex, _) in list.into_iter() {
        let current_mnemonic = Mnemonic::from_entropy(
            Entropy::from_hex(entropy_hexa.to_owned()).unwrap(),
            Language::English,
        )
        .unwrap();

        let current_seed = Seed::new(
            &current_mnemonic.get_phrase(),
            &Some(String::from("TREZOR")),
        );
        assert_eq!(mnemonic_phrase, current_mnemonic.to_string());
        assert_eq!(seed_hex, current_seed.to_hex());
    }
}

#[test]
fn create_mnemonic_from_vectors_english() {
    // Vectors validated from https://iancoleman.io/bip39/#english
    let list = vec![
        (
            WordsCount::Words12,
            "dc6c0349310df632650c891dc52920cc",
            "symbol gas spoil ginger term bomb neither muffin build citizen else odor",
            "9c91cc40b3ea91e577d301d5a0613d158b5df1c67d650e5a94d64c0fb1596d8bbf68a02c4a2413e01afb4e025db98e8c64a1963eaa2112b53c68e9871cfc4400",
            Language::English
        ),
        (
            WordsCount::Words15,
            "8fb9fdae024024a3acfe60c5c67c4750f288ac98",
            "moral soup high afraid across fade recycle slot shift crop balcony peanut chuckle film gather",
            "a428cdd413acaea0a585f63a4235d4692c1914bac7d180767fd22b4bed4935208adb553984301e310cfb4dcf2fabeccd5a3c6572e523354fae6a110534a06b99",
            Language::English
        ),
        (
            WordsCount::Words18,
            "8848296254bf80ca49f4c81025ccaa9bbff70397822727db",
            "marriage donor flat practice way gown chief october awake common click danger youth limb fun eager chief swap",
            "5d3f8e69eef4f164485a93a90bb243cb256d7b687f4e6244fc07d977c7c3d897d923570ccc575d6cb362e624a6f468ff77c5ddbe8aac78f19079233b5de48edf",
            Language::English
        ),
        (
            WordsCount::Words21,
            "5528f065635bf3f446e6fdb398daa231d736274ac170a97875d720d4",
            "festival elegant bone shop sand when breeze text receive short possible glove inflict beauty climb come practice senior into double earth",
            "e8c8a7c0ddc321a6b3f0c1c0775675e9afd94910829fc2ef5e171a0fa808b3b765bc8d8cbf0193a39cb5fd316787360e5e92aa2bac68a1dd8807287332d507fa",
            Language::English
        ),
        (
            WordsCount::Words24,
            "a1f81da593c57c367ccc01195e4d79429b1461c02a00724e37e4617fe918c91b",
            "peanut science harvest chest fit brass veteran lens bone venue furnace lunch rally couch absent divorce inch immune weekend seed write midnight caught help",
            "05f2f5b686741cb52fbc853b59cba362ea8afa23c25f8b0102d6ee611b4a3d2913ec271db7a711131e0b33f08a759f81372277282a788747ca465f2b077538c8",
            Language::English
        ),
    ];

    create_mnemonic_from_vectors_language(list);
}

#[test]
fn create_mnemonic_from_vectors_french() {
    // Vectors validated from https://iancoleman.io/bip39/#french
    let list = vec![
        (
            WordsCount::Words12,
            "e8ef3e450d3de73ecef3f9560f7225a0",
            "taxer hésiter lourd bastion sodium mouche crucial impact entourer horde kayak décrire",
            "bda2ab861fe77d7e6538127803a19da2087dde5626648dadd786557243ca419133a823bc2f8fab608bfb687a4f8f11f5a0cfac5b153fd4b6e08461cfa59708ce",
            Language::French
        ),
        (
            WordsCount::Words15,
            "c15bd671fd90891279308d2fcb4f6eb12ef9eaca",
            "primitif soldat minéral vinaigre ailier juteux surface arpenter chignon esquiver sésame faiblir trésor vague caresser",
            "e4bfb94a2c0123f109ff1801c1812ac120e71389e995b5b423dac7bca8e94e77d5d7572bb30c3f7bed1ba0eb7f0b47df430af2e803cfe22f05e6a177ad3e73f9",
            Language::French
        ),
        (
            WordsCount::Words18,
            "d1ab16a54a98631cfe95e8b2fe754413c01dd882c1b33305",
            "rondin éprouver obturer mammouth janvier ligature victoire poisson parole unitaire emballer calmer absolu tolérant amateur compact clavier caneton",
            "3f689fd3892aecc5e264703aaaf0a79364b3f4abbd6fa97b31ba1b7182bfcc9a7c641e421c1e8580f7c78441d5b029502bb091ef9eb22c0d61764178c6865811",
            Language::French
        ),
        (
            WordsCount::Words21,
            "da45d0890adfea81130bef16842d789115e10e506e1ea9459ba316d6",
            "sénateur chaton boxeur automne voter déesse écarter ignorer aveugle boueux évidence boutique éventail jeunesse délice psychose obturer cercle taureau chaise franchir",
            "df5d37e61fcaabc066f94cecfc344bb203b718d4a701c0193081b68c156243ec936d375c6bd80fb73e659314ae4c36c7d1ef84f3b0f3871a5de8a8169a1df698",
            Language::French
        ),
        (
            WordsCount::Words24,
            "dccb17fff17a318a7fc11e42b44473b17ae3bb225c6d322811b7491ad4bd150c",
            "signal éprouver zoologie studieux nautique pyramide voyelle brochure dénuder nappe bidule farfelu orifice siphon kayak libérer citoyen déesse frontal lueur orageux évoquer engager médaille",
            "728d932f21aba5e67c497ac28e489a2aed84c56333a9d29b8df236a90b8c0bd697b001084ae243c6888173e27b994e8eed9ef97fe5c3da07803209184d992786",
            Language::French
        ),
    ];

    create_mnemonic_from_vectors_language(list);
}

#[test]
fn create_mnemonic_from_vectors_italian() {
    // Vectors validated from https://iancoleman.io/bip39/#italian
    let list = vec![
        (
            WordsCount::Words12,
            "a940e3f05654803cb22c4494b220a4e4",
            "produrre alibi vitello quasi eremita bisturi seggiola nemmeno ospite onnivoro celebre selciato",
            "71803e8c6c68130ccbfda3d1d9fb04a22e66bdd48765c695aabcbd4400693b0fda6cc6d0ff4d25083cb28d0f7abb93ab901fbfae2c5d557c806eea0b9f97826f",
            Language::Italian
        ),
        (
            WordsCount::Words15,
            "e2848b17e9efd434e54819850529e3413e137848",
            "tardivo camicia sclerare sociale voragine baule oste adottare mugnaio cellulare mangiare mondina svolta rompere bretella",
            "cc277a1d64adfa9091f3878833856b34e3dfb152f1aa203549c841d09f71268bf2c5a9155ffea261b00ec87759c585829b6c413da0d25f0cd6bf16b83c8b1233",
            Language::Italian
        ),
        (
            WordsCount::Words18,
            "78e9be08f3b769d63a5e9378cdbfca8aab7eb271acca42af",
            "manifesto fango monastero titubante macchina trarre tortora smeraldo mangiare labirinto usuraio attrito ripieno funzione scorta parcella edile materasso",
            "125f1802f7d1ec9b8edb6b58144a25bc518cdc86d1a291d592fdea8b3d42c078be92222decd69ea82790990415344ec7cd7b684f043f8bb54526d978407aac4e",
            Language::Italian
        ),
        (
            WordsCount::Words21,
            "805945fd8c4636fb912ab4b99dceb7276fa21f07c094a6a69273e0fa",
            "missiva sempre mimosa balena ibernato metallo elsa fracasso ritardo turbare ragione fastoso vile aragosta bordo asepsi potassio critico perbene sbalzo profumo",
            "54fcb70b713cbe1b7f0a7d6eebe7a2061bf698986728dbad00c824b25f5eecd3f56cd94ec455d6e6403909f694a3b05f3867fa0ecaa145fcd35136510b516b43",
            Language::Italian
        ),
        (
            WordsCount::Words24,
            "72b9fa11031f36c770c2f6e6edb58a04d3cd13a60160fa9a5c3fe82f2f6a7d72",
            "limpido silenzio movimento albume vagabondo identico sbrinare girato tiraggio iterare gruppo ambito diradare ninfa palesare cifrare vincitore smussato aratura simulato utilizzo riforma vasca globulo",
            "29083d421634e1c1d84ebeebc1c7a9faaa018b97c7b589a0491fb258d051c6a3de723144c09dfbc22374fba35a423899201c794f0c91dcd16c00a5a8a5b465f7",
            Language::Italian
        ),
    ];

    create_mnemonic_from_vectors_language(list);
}

#[test]
fn create_mnemonic_from_vectors_portugese() {
    // Vectors validated from https://iancoleman.io/bip39/#portuguese
    let list = vec![
        (
            WordsCount::Words12,
            "244ffa28ea324838a19405a33ded4ddf",
            "bimestre impedir julho rosado biologia avisar ironizar inapto motel trama ejetar poeira",
            "b481e3f7797ce993e851b226e5d4c8f09dfa481c99375cb53ea0f7d17669414a47c5709f515d503d5645f0f50bac2bcb7777511df9af3b10b6603982433eb61f",
            Language::Portugese
        ),
        (
            WordsCount::Words15,
            "d92a67c1442993ec2cbceacf23f1de5d21af47e0",
            "sangue efeito tremer javali maresia valores padaria mergulho reparo banquete graveto pertence aura mulata inimigo",
            "b2a5da4148bb901a55631dce9287e000be0b522cb636381d300f1933f657d6dc9761ff8109b9baefa19df51ff1bedc916034d7e4e07067a5bc2c52268712bd44",
            Language::Portugese
        ),
        (
            WordsCount::Words18,
            "e6c89b02941d3c48fac7d1b19f61e27a6344868496a49568",
            "tamborim curral pote borda rodovia bimotor textura viaduto outono viela grosso usado celular cubano anuidade roseira macaco deboche",
            "fbcee34d49efd0700287f83156a3635f1a4824811c9923e1363ccd7d005270a9b7c0b16f96164639d8c726051efda733b007ffc5adccd7d10fc85b3ce5142e1c",
            Language::Portugese
        ),
        (
            WordsCount::Words21,
            "99da99bbf9fe031171219923fb1489b0e95c34bba6511dd4c0e422a0",
            "maroto rota funil unha soletrar joaninha provador caule bifurcar sambar bengala exonerar macio atriz toupeira rasgar bagagem nativa ciranda custear abelha",
            "ee266d5718fc96219f44a5d0df594dd92c2a8d140d2b0ef5bb7d29f97d4d424c0cd64d7e7cb9558181c722dbd6c9b35df3de8a4fea737a25dec722ba7ebfb45a",
            Language::Portugese
        ),
        (
            WordsCount::Words24,
            "a25abba0e5a9f24f260a97c9867d09d6558b6fcc99f77c70ea206e88db678675",
            "morango rugido taurino rebaixar milenar bombeiro manivela edital raposa cedilha criminal oferenda enrugar pegada casca copeiro hoje janeiro jasmim seringa lavoura palavra ativo nevasca",
            "77ede48bc9ee8d008cf07d55224b9669f750cb5b3365c3d7c68ed286af6d9cd8ca7aa8d93e2ae2bd64164635c99a8b72ca774f53c1955ff2b8dd4a1171826a4d",
            Language::Portugese
        ),
    ];

    create_mnemonic_from_vectors_language(list);
}

#[test]
fn create_mnemonic_from_vectors_spanish() {
    // Vectors validated from https://iancoleman.io/bip39/#spanish
    let list = vec![
        (
            WordsCount::Words12,
            "6d79db09693fa7c42e8e7aae2f3dc029",
            "hongo ruleta rayo sanidad vigor tarot pregunta ruptura pedal laguna hurto exponer",
            "49d9ab8e54a9003d3dfce512a3ef674e04417d645cf1ed147b232ce52975b60b44be3d1c1187569edd90315e53e69d383f526bd8548f636d2314378cc6985050",
            Language::Spanish
        ),
        (
            WordsCount::Words15,
            "627a7e030a47b8b74b48113e520e854fdaeb0a97",
            "gemelo seco líquido asilo lata fobia cazo acento curioso misil oferta ocho pelar maceta freír",
            "7d5ef997137de1d550b22e3c0a71e57b8d4c3615f8538cb2988d0dc6b65a1a396d7cb63ddcde5c59e3f8c2f8506c8e743cd2a9ca2b69020f02428e127a9719c8",
            Language::Spanish
        ),
        (
            WordsCount::Words18,
            "b0713518312fe7d9e709b02b895b3cdac9610d09184ac139",
            "pera mármol don gavilán yerno tráfico noticia colegio carne élite rumor placa muñeca maldad búho aliado rampa reunir",
            "885cebbe9fde40da4cfba3d322312c12f4cd4bb22cfa137ee1dd2eca78ab4f546596f86b04aea413d472db1f90fabaeb7c29d1b30527a52a4cbdf30411e2fb80",
            Language::Spanish
        ),
        (
            WordsCount::Words21,
            "ba85978972fc434452f10728b7a888660d496f027e21ba1f288f0d4e",
            "preso catorce tarta tesoro redondo ola empeño bonsái camino pueblo brazo rodilla seis poeta almíbar redondo precoz viaje bucle bache típico",
            "273a98d3bda309e6aea194f892053c020e3fdd8bea59069eeac9fc6039d236ee2bea333c0707e441b3475f7eb744233f862fa0e4ee22987423f017277ec6ebba",
            Language::Spanish
        ),
        (
            WordsCount::Words24,
            "c53f1e3818464d446827a042b79d127ae5655a74897fa2c30f0e3ce7fcff5835",
            "regla verso metro chivo goloso ola ocurrir vaca día público dinero variar fauna pausa sanear chancla olmo ave recoger lágrima limón límite galería pétalo",
            "08e56faf1b883737869f4fdbf35534202b760c80d898c8f8baa2cdd084b0c88e4c5c1bd4e20a478864e5dd83d3e59b1a80184551b17381811886d90c2544190e",
            Language::Spanish
        ),
    ];

    create_mnemonic_from_vectors_language(list);
}

#[test]
fn create_mnemonic_from_vectors_czech() {
    // Vectors validated from https://iancoleman.io/bip39/#czech
    let list = vec![
        (
            WordsCount::Words12,
            "1fc165be09f86cc218a6cb73c98d5919",
            "dolar bokorys mudrc chirurg ohnisko loket lstivost ubrat naopak koberec krutost hlava",
            "23f66136674841ea4f26139c60796224c736176e19d6ecd204bf6663dde7a15900b36d39e140289b52e02c20a97f620f75f56fcf3c9470b5c0bb9a85dd298a52",
            Language::Czech
        ),
        (
            WordsCount::Words15,
            "09e615ad5a262970d9c00b0715e3fb686ff14d71",
            "blokovat hanopis mluvit rozchod lstivost sardinka mazlit anekdota beran ratolest ztratit tavenina zubr praktika sobota",
            "3cfeb3a1c4d5a2eed8893dc3ead3b2c2a7192d848206c61f151603970c7bf2e3bc75fc9a8c7a39ef140b4a00eed502730a866dd8665ea8991fb996a902309015",
            Language::Czech
        ),
        (
            WordsCount::Words18,
            "31bdab515bfbd9d0386e84fae89f3e20369a516eddc69ba2",
            "hektar vyplatit topol samec sirup voskovka vejce tanker zmar kalnost tajga jednatel mimika euforie seslat sazba podepsat chapadlo",
            "2a573ead25dd2dc01efa00e78bb1116af41a2f0c1aee90c5ab58db3d9f3f120d7673a98fd72dff5425495227b7bbcf5b8232462719506337cd2b5f41c93790fa",
            Language::Czech
        ),
        (
            WordsCount::Words21,
            "c866375dd6683cd6a3d789ed6e90be9e6561f7f4cc8f017864b8538c",
            "srpen hektar trvat pysk odliv mluvit ovanout vzpoura vypravit naposled grog ikona kruhadlo znak tkadlec panovat anekdota smrad genetika praporek spojenec",
            "4614a852a91077b9858971a1dc7b756ac461c72c3cd0d40fa6e1939f4102525ac06f5c725052007df12ec372f39f2366e33cac1e05a8b135b0565b7f17554f7e",
            Language::Czech
        ),
        (
            WordsCount::Words24,
            "0ff864e071bad877cc79944f1e8207439d9b298c713d13fd4cca257a58fd1e0b",
            "burza smrad hotovost veterina radon hybnost hematom historik koncept zanechat ochrana ohryzek ubrus pendrek helma epocha chirurg vychovat historik klokan povyk obliba neochota nepokoj",
            "997f09c72b3a71f6bfc254ceb04af7d923d41c1ca0225e384b4dae8ba99d0ef2cf0bd99c555fedd7a17332a88f65def954fdc3f0d29f072d3278db8d8f70dfb9",
            Language::Czech
        ),
    ];

    create_mnemonic_from_vectors_language(list);
}

#[test]
fn create_mnemonic_from_vectors_japanese() {
    // Vectors validated from https://iancoleman.io/bip39/#japanese
    let list = vec![
        (
            WordsCount::Words12,
            "6380163837921d15504675b5b988cc69",
            "したみ あきる たりきほんがん すごい おくる たたみ けいれき ひめじし ぬかす ひつじゅひん きせつ ぷうたろう",
            "941530ba07db979119fa7c50218e3a19b404b3269018472f0a33887282c6bd8594660e621a7301959d5829f1d97b41cf583ea71dcdf6c48ba43d3bbc18c5c342",
            Language::Japanese
        ),
        (
            WordsCount::Words15,
            "21a4662f8df81397a60b40de57a19c201b491c07",
            "おくりがな おじさん たにん えすて そぼろ ひたる ついたち しもん ほたて のせる しほん けいかく にんち たりきほんがん えんぎ",
            "f1c00ce3275d5971eda50c037c2ca4b314f092eb659225bef5b850d81f714eb56b28ffd40e9f9321472cec859188b740aadf3a54d81a44946e0a0f264271f5aa",
            Language::Japanese
        ),
        (
            WordsCount::Words18,
            "a7c5f9b069546fa528f294c1b89d6986b3e1910d02b6cf97",
            "とける きおう しらせる ふおん けまり ふえる でんち こねこね はくしゅ はっぽう さくひん いとこ くのう はんぶん きつつき こんすい ひりつ ねぼう",
            "db1678a8e0e984dadeb5cf2b8d1868ba7cb6f11e93128ed67ca3dbdef10648815e1cc1be84c79964cd92ae01380c85a2c09bdd4b24e77ef91baca16226ff2540",
            Language::Japanese
        ),
        (
            WordsCount::Words21,
            "c26bf7246667933e09b71783717a1e973686b7029516642359853c1b",
            "ばしょ さんいん はんらん ぴっちり せんげん てさぎょう おんしゃ まんきつ そんみん たなばた たいら かんそう しゃおん ざっか いぜん てんかい しつもん えいぶん しあい せもたれ のぼる",
            "f24f64441443c646a72f1c6418f00dd77ed88ded7f1f697f22f6a515754b66c58f1c22047e44ca2d6af7d3dfcae800fa7113e201a5c46f1da8f331649bc89f75",
            Language::Japanese
        ),
        (
            WordsCount::Words24,
            "3fbdf874d961c78040356471ca73d5aa2c98291e6387aea4671fb39a497c9e01",
            "ぐんしょく やたい えりあ にまめ えほん はいしん あけがた なこうど ずほう こぼれる よやく こむぎこ ひえる うしなう せんしゅ すばらしい なやむ おじさん ぱんつ しまう てんめつ のみもの せめる きおち",
            "566b518cf39f4d2254beee956c1fbc78d4b87538d9813e1573cfcf37e102e2a54336ea20b79709de8d745eeee5ad3cb39b42ff4b4b747ce738d7b92d89ce7eb0",
            Language::Japanese
        ),
    ];

    create_mnemonic_from_vectors_language(list);
}

#[test]
fn create_mnemonic_from_vectors_korean() {
    // Vectors validated from https://iancoleman.io/bip39/#korean
    let list = vec![
        (
            WordsCount::Words12,
            "a5cf0eb6756ab6b767ed8ed4b1989c29",
            "이렇게 시댁 일행 프린터 일단 비율 월세 작품 체계 여덟 냉동 본격적",
            "92b90c0b364ca34a400078d3acb9a6cf04cb3b0c7469e7b0cc225ad45046c6083837c5f46ca4beea24012951c470d080fb91539c19592974432de4762dedaa0d",
            Language::Korean
        ),
        (
            WordsCount::Words15,
            "389abbad34557bb7e1455a1b923d7195590c0b82",
            "만화 초상화 피아노 설렁탕 분량 칠판 안방 일기 그늘 염려 빗방울 느낌 연합 강원도 결론",
            "cc2763cc65d4bb90058fcd60671d3356be81492a5566f48db20353ae13b565c747f9e597452b95848098acfd457deb24c6aa6cd87d33a891d172337995cc6beb",
            Language::Korean
        ),
        (
            WordsCount::Words18,
            "47c5e1b587d6e4e5f77899cb544451c56c3cf7b9ef84f033",
            "반지 당장 소원 골목 속담 수준 코끼리 과학 지적 육군 관점 업무 종종 식료품 편견 한때 한낮 온종일",
            "f5c0b3f197960b83a4f0a7714c16adf6308f29fcb69ee9d712222abc2176af0b5d65364ce666575c344025f588672fd461ff9abe51cb9bc3482692e14e42514a",
            Language::Korean
        ),
        (
            WordsCount::Words21,
            "9a788ab74d4d74260e3fb9d581f206511b8da59a2f19e8ef1cdcf82e",
            "외로움 주관적 임금 외삼촌 촬영 과정 말씀 혈액 초반 곡식 씨름 육군 전공 처음 설렁탕 통역 평화 시부모 마흔 한눈 터미널",
            "84ff2bff3ec509e21146f3729b8b4b719ea60767418b44b0c1a82604f8f5136c34bf9bd7849db4947e27b83b622706488d39a5253f48c3f3566fb75da70fa7f7",
            Language::Korean
        ),
        (
            WordsCount::Words24,
            "d9ae5709d1352f3d2ae47d1fee04dc1f90c56ee758ef5c9965ede8ad999c0205",
            "출신 수영 조정 육십 복도 원고 일대 연속 기록 솜씨 마찰 몸속 경치 저렇게 운반 글자 빗줄기 지원 식기 창문 출산 집단 걱정 유형",
            "747de19a6280384bbd7ef7476e7d788b7b5f8b83cf56ddba15bec92b203ed29f3b9fa97eac7c9446f8a9e2ba949ce5365f826c3c35be27c2718cc2e0c6d11538",
            Language::Korean
        ),
    ];

    create_mnemonic_from_vectors_language(list);
}

fn create_mnemonic_from_vectors_language(list: Vec<(WordsCount, &str, &str, &str, Language)>) {
    // Vectors validated from https://iancoleman.io/bip39
    for (words_count, entropy_hexa, mnemonic_phrase, seed_hex, lang) in list.into_iter() {
        let current_mnemonic = Mnemonic::from_entropy(
            Entropy::from_hex(entropy_hexa.to_owned()).unwrap(),
            lang,
        )
        .unwrap();

        let current_seed = Seed::new(
            &current_mnemonic.get_phrase(),
            &None,
        );
        assert_eq!(mnemonic_phrase, current_mnemonic.to_string());
        //Get EntropySizeFrom from usize and tranform into WordCount (can be simplified, I know :P)
        assert_eq!(WordsCount::from(current_mnemonic.get_words().len()), words_count);
        assert_eq!(seed_hex, current_seed.to_hex());
    }
}