use eth_bn254_keystore::{decrypt_key, encrypt_key, new};
use hex::FromHex;
use std::path::Path;

mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::thread_rng();
        let (secret, id) = new(&dir, &mut rng, "thebestrandompassword", None).unwrap();

        let keypath = dir.join(&id);

        assert_eq!(
            decrypt_key(&keypath, "thebestrandompassword").unwrap(),
            secret
        );
        assert!(decrypt_key(&keypath, "notthebestrandompassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[test]
    fn test_new_with_name() {
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::thread_rng();
        let name = "my_keystore";
        let (secret, _id) = new(&dir, &mut rng, "thebestrandompassword", Some(name)).unwrap();

        let keypath = dir.join(&name);

        assert_eq!(
            decrypt_key(&keypath, "thebestrandompassword").unwrap(),
            secret
        );
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_decrypt_scrypt() {
        let secret =
            Vec::from_hex("0ba5cd0250357a2e0c0ff2d2dee3ea3873bbcf9041e3206836a839549b8eac6b")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/test.bls.key.json");
        assert_eq!(decrypt_key(&keypath, "1234").unwrap(), secret);
        assert!(decrypt_key(&keypath, "thisisnotrandom").is_err());
    }

    #[test]
    fn test_encrypt_decrypt_key() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::thread_rng();
        let name = encrypt_key(&dir, &mut rng, &secret, "newpassword", None).unwrap();

        let keypath = dir.join(&name);
        assert_eq!(decrypt_key(&keypath, "newpassword").unwrap(), secret);
        assert!(decrypt_key(&keypath, "notanewpassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
    }
}
