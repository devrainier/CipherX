# CipherX


CipherX is a simple, custom encryption and decryption program inspired by AES. 
It incorporates elements like S-box substitution, ShiftRows, MixColumns, Galois Field (GF) multiplication and xtime operations but it is built entirely from scratch with custom modifications, **not** following the standard AES specification.


**Important:** 
This is an **educational and experimental project only**. 
It has **not** been cryptographically audited and should **not** be used to protect sensitive or real-world data.


## Current Features


- Encryption and decryption of byte arrays (strings, raw data, etc.)
- File encryption and decryption support
- Multithreaded processing for better performance on larger inputs
- Key derivation from username + password combination
- Simple, straightforward API


## How to Use


1. Clone or download the project
   ```bash
   git clone https://github.com/devrainier/CipherX
   ```
3. Open a terminal in the project folder
4. Run the example: `cargo run --release`


To encrypt or decrypt real files, edit `main.rs` and uncomment the file-processing lines:
```rust
// for file using same username & password


cipherx.set_mode("encrypt");
ciherx.file("sample.txt");    // creates sample.txt.enc file


cipherx.set_mode("decrypt");
cipherx.file("sample.txt.enc");   // restores sample.txt


```
Then run again: `cargo run --release`


## Project Status
  - My first real Rust project 
  - Still very much a learning or hobby implementation
  - Planning to possibly refactor it into a proper library + CLI tool later
  - Very open to feedback: code structure, bugs, performance ideas, safety concerns, naming, etc.


## License
MIT License
