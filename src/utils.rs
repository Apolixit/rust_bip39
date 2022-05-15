use hmac::Hmac;
use sha2::{Sha256, Digest};
use pbkdf2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Pbkdf2
};

/// Apply the SHA256 has function
pub fn sha256(bytes: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

pub fn Pbkdf2_hash(password: Vec<u8>, salt: Vec<u8>) -> Vec<u8> {
    let mut seed = vec![0u8; 64];
        pbkdf2::pbkdf2::<Hmac<sha2::Sha512>>(
            &password,
            &salt,
            2048,
            &mut seed,
        );

    seed
}


#[cfg(test)]
mod tests {
    use crate::{utils, entropy::Entropy};

    #[test]
    fn test_sha256() {
        let inputs = vec![
            (
                "toto",
                "31f7a65e315586ac198bd798b6629ce4903d0899476d5741a9f32e2e521b6a66",
            ),
            (
                "bitcoin",
                "6b88c087247aa2f07ee1c5956b8e1a9f4c7f892a70e324f1bb3d161e05ca107b",
            ),
            (
                "substrate",
                "df5e69a6000eaee68a8f7f7baa620ac6401fef79ba563ff7acec9d4ecef7888b",
            ),
            (
                "ethereum",
                "b60d7bdd334cd3768d43f14a05c7fe7e886ba5bcb77e1064530052fed1a3f145",
            ),
        ];
        for input in inputs {
            assert_eq!(
                input.1,
                hex::encode(utils::sha256(&input.0.as_bytes().to_vec()))
            )
        }

        // And we test SHA256 on default entropy
        // println!("{:X?}", Entropy::default().entropy.val);
        // println!("{:X?}", Mnemonic::sha256(&Entropy::default().entropy.val));
        // println!("{:X?}", hex::encode(Mnemonic::sha256(&Entropy::default().entropy.val)));
        assert_eq!(
            hex::encode(utils::sha256(&Entropy::default().entropy.val)),
            "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
        );
    }
}