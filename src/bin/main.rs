use cipherx::CipherX;


fn main() {
    // sample implementation 

    let mut cipherx = CipherX::new("devrainier", "pass1234qwerty");    // add first username & password

    let string = "Hello world";
     println!("\nString : {}", string);

    let data = string.as_bytes();   
    println!("\nRaw Data : \n{:?}", &data);

    cipherx.set_mode("encrypt");    //  default mode=encrypt
    let encrypted = cipherx.process(&data); // now proceed to encryption
    println!("\nEncrypted : \n{:?}", &encrypted);

    cipherx.set_mode("decrypt");    // to decrypt just set first mode to decrypt
    let decrypted = cipherx.process(&encrypted);     
    println!("\nDecrypted : \n{:?}", &decrypted);

    assert_eq!(&data, &decrypted);
    
    let result = String::from_utf8(decrypted).unwrap();
    println!("\nDecrypted String: {:?}", result);


    // for file using same username & password

    // cipherx.set_mode("encrypt");
    // cipherx.file("sample.txt");    // creates sample.txt.enc file
    
    // cipherx.set_mode("decrypt");
    // cipherx.file("sample.txt.enc");   // restores sample.txt



}

