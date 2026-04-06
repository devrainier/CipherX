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
    let _ = cipherx.file(path);

    let decrypted = fs::read(path).unwrap();
    assert_eq!(original, decrypted);

    let _ = fs::remove_file(path).unwrap();
    let _ = fs::remove_file("sample.txt.enc").unwrap();
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
    let _ = cipherx.file(path);

    let data = fs::read("empty.txt.enc").unwrap();
    assert_eq!(&data, "".as_bytes());

    let _ = fs::remove_file(path).unwrap();
    let _ = fs::remove_file("empty.txt.enc").unwrap();

}	

#[test]
fn test_large_input() {
    let mut cipherx = CipherX::new("devrainier", "pass2222");
    let data = vec![0u8; 100_000_000]; 

    let encrypted = cipherx.process(&data);

    cipherx.set_mode("decrypt");
    let decrypted = cipherx.process(&encrypted);

    assert_eq!(decrypted, data);
}


#[test]
fn test_single_data() {                                                         let mut cipherx = CipherX::new("devrainier", "pass2222");
    let data = vec![1u8; 1];

    let encrypted = cipherx.process(&data);

    cipherx.set_mode("decrypt");
    let decrypted = cipherx.process(&encrypted);

    assert_eq!(decrypted, data);

}


#[test]
fn test_various_patterns_roundtrip() {
    let mut cipherx = CipherX::new("devrainier", "mypass");

    for len in 1..=255 {
      
        let data: Vec<u8> = (0..len)
            .map(|i| ((i * 31 + len) % 256) as u8)
            .collect();

        cipherx.set_mode("encrypt");
        let enc = cipherx.process(&data);

        cipherx.set_mode("decrypt");
        let dec = cipherx.process(&enc);

        assert_eq!(dec, data);
    }
}


#[test]
fn test_edge_patterns_roundtrip() {
    let mut cipherx = CipherX::new("devrainier", "mypass");
 
    let patterns = vec![
        vec![0u8; 256],    // all zeros
        vec![255u8; 256],    // all max
        (0..=255).collect(),    // ascending
        (0..=255).rev().collect(),    // descending
    ];

    for data in patterns {
        cipherx.set_mode("encrypt");
        let enc = cipherx.process(&data);

        cipherx.set_mode("decrypt");
        let dec = cipherx.process(&enc);

        assert_eq!(dec, data);
    }
}
   

#[test]
fn test_file_binary_roundtrip() {
    
    let path = "binary_file.bin";

    let data: Vec<u8> = (0..=255).cycle()
        .take(1024)
        .collect();

    fs::write(path, &data).unwrap();

    let mut cipherx = CipherX::new("devrainier", "mypass");

    cipherx.set_mode("encrypt");
    let _ = cipherx.file(path);

    cipherx.set_mode("decrypt");
    let _ = cipherx.file("binary_file.bin.enc");

    let dec = fs::read(path).unwrap();
    assert_eq!(dec, data);

    let _ = fs::remove_file(path).unwrap();
    let _ = fs::remove_file("binary_file.bin.enc").unwrap();
}


#[test]
fn test_file_roundtrip_non_block_size() {
   
    let path = "non_block_file.bin";
    let data = vec![3u8; 1023];

    fs::write(path, &data).unwrap();

    let mut cipherx = CipherX::new("devrainier", "mypass");

    cipherx.set_mode("encrypt");
    let _ = cipherx.file(path);

    cipherx.set_mode("decrypt");
    let _ = cipherx.file("non_block_file.bin.enc");

    let dec = fs::read(path).unwrap();
    assert_eq!(data, dec);

    let _ = fs::remove_file(path);
    let _ = fs::remove_file("non_block_file.bin.enc");
}


#[test]
fn test_file_roundtrip_large_threaded() {

    let path = "large_file.bin";
    let data: Vec<u8> = (0..=255).cycle()
        .take(5_000_000)
        .collect();

    fs::write(path, &data).unwrap();

    let mut cipherx = CipherX::new("devrainier", "mypass");

    cipherx.set_mode("encrypt");
    let _ = cipherx.file(path);

    cipherx.set_mode("decrypt");
    let _ = cipherx.file("large_file.bin.enc");

    let dec = fs::read(path).unwrap();
    assert_eq!(data, dec);

    let _ = fs::remove_file(path);
    let _ = fs::remove_file("large_file.bin.enc");
}


#[test]
fn test_file_roundtrip_binary_entropy() {
    
    let path = "entropy.bin";
    let data: Vec<u8> = (0..=255).cycle()
        .take(4097)
        .collect();

    fs::write(path, &data).unwrap();

    let mut cipherx = CipherX::new("devrainier", "mypass");

    cipherx.set_mode("encrypt");
    let _ = cipherx.file(path);

    cipherx.set_mode("decrypt");
    let _ = cipherx.file("entropy.bin.enc");

    let dec = fs::read(path).unwrap();
    assert_eq!(data, dec);

    let _ = fs::remove_file(path);
    let _ = fs::remove_file("entropy.bin.enc");
}


#[test]
fn test_file_wrong_credentials_fail() {

    let path = "wrong_file.bin";
    let data = vec![5u8; 5000];

    fs::write(path, &data).unwrap();

    let mut cipherx = CipherX::new("devrainier", "mypass");
    let _ = cipherx.file(path);

    let mut cipherx2 = CipherX::new("user2", "pass2");
    cipherx2.set_mode("decrypt");
    let res = cipherx2.file("wrong_file.bin.enc");
   
    assert!(res.is_err());

    let _ = fs::remove_file(path).unwrap();
    let _ = fs::remove_file("wrong_file.bin.enc");
}


