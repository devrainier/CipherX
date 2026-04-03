use std::fs;
use cipherx::*;

#[test]
fn test_encrypt_decrypt() {
    let mut cipherx = CipherX::new("devrainier", "pass1234qwerty"); 

    let data = "Hello world".as_bytes(); 
    let encrypted = cipherx.process(data); 

    cipherx.set_mode("decrypt"); 
    let decrypted = cipherx.process(&encrypted);
  
    assert_eq!(&data, &decrypted);

}


#[test]
fn test_encrypt_different_keys() {
    let data = "Hello world".as_bytes();
    let cipherx = CipherX::new("devrainier", "pass1234qwerty");
    let encrypted = cipherx.process(data);

    let data2 = "Hello world".as_bytes();
    let cipherx2 = CipherX::new("devrainier", "newpass9876");
    let encrypted2 = cipherx2.process(data2);
    
    assert_ne!(&encrypted, &encrypted2);

}


#[test]
fn test_encrypt_decrypt_file() {

    let path = "sample.txt";
    let original: Vec<u8> = "hello file test".as_bytes().to_vec();
    
    fs::write(path, &original).unwrap();
    
    let mut cipherx = CipherX::new("devrainier", "mypass1234");
    cipherx.file(path);

    let decrypted = fs::read(path).unwrap();
    assert_eq!(original, decrypted);

    fs::remove_file(path).unwrap();
    fs::remove_file("sample.txt.enc").unwrap();
}


#[test]
fn test_wrong_credentials_fail() {
    let data = "secret data".as_bytes();

    let cipherx = CipherX::new("devrainier", "pass1234");
    let mut cipherx2 = CipherX::new("new_user", "1234pass");

    let encrypted = cipherx.process(data);

    cipherx2.set_mode("decrypt");
    let decrypted = cipherx2.process(&encrypted);

    assert_ne!(decrypted, data);
}


#[test]
fn test_empty_input() {
    let mut cipherx = CipherX::new("devrainier", "passqwerty");
    let data = "".as_bytes();

    let encrypted = cipherx.process(data);

    cipherx.set_mode("decrypt");
    let decrypted = cipherx.process(&encrypted);

    assert_eq!(decrypted, data);
}


#[test]
fn test_empty_file() {
    let path = "empty.txt";
    fs::write(path, "".as_bytes()).unwrap();

    let mut cipherx = CipherX::new("devrainier", "pass1111");
    cipherx.file(path);

    let data = fs::read("empty.txt.enc").unwrap();
    assert_eq!(&data, "".as_bytes());

    fs::remove_file(path).unwrap();
    fs::remove_file("empty.txt.enc").unwrap();

}	

/*
#[test]
fn test_large_input() {
    let mut cipherx = CipherX::new("devrainier", "pass2222");
    let data = vec![0u8; 104_857_600]; // 100 MB

    let encrypted = cipherx.process(&data);

    cipherx.set_mode("decrypt");
    let decrypted = cipherx.process(&encrypted);

    assert_eq!(decrypted, data);
}
*/
