use std::sync::Arc;	
use std::fs::{self, File};
use std::thread;
use std::io::{self, BufReader, BufWriter, Read, Write, Seek, SeekFrom};


use super::table::{SBOX, INV_SBOX, SHIFT_ROWS, INV_SHIFT_ROWS};


static MUL2: [u8; 256] = create_table(2);
static MUL3: [u8; 256] = create_table(3);
static MUL9: [u8; 256] = create_table(9);
static MUL11: [u8; 256] = create_table(11);
static MUL13: [u8; 256] = create_table(13);
static MUL14: [u8; 256] = create_table(14);


const fn create_table(num: u8) -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i: usize = 0;

    while i <= 255 {
        table[i] = gf_mul(num, i as u8);
        i += 1;
    }

    table    
}


const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;

    while b > 0 {
        if b & 1 == 1 {
            result ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }

    result
}


const fn xtime(a: u8) -> u8 {
    let shifted = (a as u16) << 1;
    let result = shifted as u8;

    if a >= 128 {
        result ^ 27
    } else {
        result
    }
}


pub struct CipherX {
    master_key: [u8; 32],
    expanded_key: Arc<Vec<[u8; 16]>>, 
    mode: bool,
    stream: bool,
}


impl CipherX {

   const RCON: [u8; 10] = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54];


    pub fn new(username: &str, pass: &str) -> Self {
                
        let mut pre_salt = Self::create_32_bytes(username.as_bytes()); 
        let mut pre_pass = Self::create_32_bytes(pass.as_bytes());
        
        let mut salt = Self::create_salt(&mut pre_pass, &mut pre_salt);
        let master_key = Self::create_master_key(&mut pre_pass, &mut salt);
        let expanded_key = Self::create_expanded_key(&master_key);
        
        Self {
            master_key: master_key,
            expanded_key: Arc::new(expanded_key),
            mode: true,
            stream: false,
        }
    }

    
    fn create_32_bytes(pass: &[u8]) -> [u8; 32] {
        let mut block = [0u8; 32];

        for (i, val) in block.iter_mut().enumerate() {
            let j = i % pass.len();
            let s_val = &SBOX[i];
            let p_val = pass[j];

            let data: u8 = p_val.wrapping_add(i as u8)
                .wrapping_add(*s_val);

            *val = data.wrapping_add(*s_val) ^ p_val;
        }

        block
    }
    
    
    fn create_salt(pass: &mut [u8; 32], salt: &mut [u8; 32]) -> [u8; 32] {
  
        let (l_pass, r_pass) = pass.split_at_mut(16);
        let (l_salt, r_salt) = salt.split_at_mut(16);

        for _ in 0..5_000 {
            Self::encrypt_helper(l_pass, l_salt);
        }

        for _ in 0..5_000 {
            Self::encrypt_helper(r_pass, r_salt);
        }

        *salt
    }


    fn create_master_key (pass: &mut [u8; 32], salt: &mut [u8; 32]) -> [u8; 32] {

        Self::create_salt(pass, salt);

        let mut pre_expanded_key = Self::create_expanded_key(salt);

        Self::encrypt(&pre_expanded_key, &mut salt[..16]);
        Self::encrypt(&pre_expanded_key, &mut salt[16..]);
       
        pre_expanded_key = Self::create_expanded_key(salt);

        let (l_salt, r_salt) = salt.split_at_mut(16);

        for _ in 0..5_000 {
            Self::encrypt(&pre_expanded_key, l_salt);
        }       

        for _ in 0..5_000 {
            Self::encrypt(&pre_expanded_key, r_salt);
        }

        *salt

    }



    fn create_expanded_key(master_key: &[u8; 32]) -> Vec<[u8; 16]> {
    
        let mut words: Vec<[u8; 4]> = master_key
            .chunks_exact(4)
            .map(|chunk| {
                let mut word = [0u8; 4];
                word.copy_from_slice(chunk);
                word
            })
            .collect();

        let mut rcon_counter: usize = 0;

    
        while words.len() < 60 {
            let mut temp = words[words.len() - 1]; 

            let i = words.len(); 

            if i % 8 == 0 {
                temp = [temp[1], temp[2], temp[3], temp[0]]; 

                for byte in temp.iter_mut() {
                    *byte = SBOX[*byte as usize];
                }

                temp[0] ^= Self::RCON[rcon_counter];
                rcon_counter += 1;
            } 
            else if i % 8 == 4 {
                for byte in temp.iter_mut() {
                    *byte = SBOX[*byte as usize];
                }
            }

            let prev = words[i - 8];
            let new_word = [
                prev[0] ^ temp[0],
                prev[1] ^ temp[1],
                prev[2] ^ temp[2],
                prev[3] ^ temp[3],
            ];

            words.push(new_word);
        }

        let mut round_keys = Vec::with_capacity(15);

        for i in 0..15 {
            let mut key = [0u8; 16];
            let base = i * 4; 

            for j in 0..4 {
                let word = &words[base + j];
                key[j*4..(j+1)*4].copy_from_slice(word);
            }

            round_keys.push(key);
        }

        round_keys

    }


    pub fn get_master_key(&self) -> &[u8] {
        &self.master_key
    }


    pub fn get_expanded_key(&self) -> &Vec<[u8; 16]> {
        &*self.expanded_key
    }


    fn add_round_key(keys: &[u8], block: &mut [u8]) {
   
        for (i, val) in block.iter_mut().enumerate() {
            *val = *val ^ keys[i]
        }

    }


    fn sub_bytes (block: &mut [u8], table: &[u8; 256]) {

        for val in block.iter_mut() {
            *val = table[*val as usize];
        }

    }


    fn shift_rows(block: &mut [u8], table: &[usize; 16]) {
        
        let vec = block.to_vec();
        let mut pos: usize;

        for (i, val) in block.iter_mut().enumerate() {
            pos = table[i];
            *val = vec[pos];
        }

    }


    fn mix_column(block: &mut [u8], mode: bool) {
       
        for col in block.chunks_mut(4) {
            let a = col[0];
            let b = col[1];
            let c = col[2];
            let d = col[3];

            if mode {            
                
                col[0] = MUL2[a as usize] ^ MUL3[b as usize] ^ c ^ d;
                col[1] = a ^ MUL2[b as usize] ^ MUL3[c as usize] ^ d;
                col[2] = a ^ b ^ MUL2[c as usize] ^ MUL3[d as usize];
                col[3] = MUL3[a as usize] ^ b ^ c ^ MUL2[d as usize];
                
            } else {

                col[0] = MUL14[a as usize] ^ MUL11[b as usize] ^ MUL13[c as usize] ^ MUL9[d as usize];
                col[1] = MUL9[a as usize] ^ MUL14[b as usize] ^ MUL11[c as usize] ^ MUL13[d as usize];
                col[2] = MUL13[a as usize] ^ MUL9[b as usize] ^ MUL14[c as usize] ^ MUL11[d as usize];
                col[3] = MUL11[a as usize] ^ MUL13[b as usize] ^ MUL9[c as usize] ^ MUL14[d as usize];

            }
            
        }
    }


    fn encrypt_helper(keys: &[u8], block: &mut [u8]) {
        Self::sub_bytes(block, &SBOX);
        Self::shift_rows(block, &SHIFT_ROWS);
        Self::mix_column(block, true);
        Self::add_round_key(keys, block);
    }


    fn encrypt(expanded_keys: &Vec<[u8; 16]>, block: &mut [u8]) {

        let master_key = &expanded_keys[0];

        Self::add_round_key(master_key, block);
        
        for i in 1..=13 {
            let keys = &expanded_keys[i];
            Self::encrypt_helper(keys, block);        
        }
        
        let final_key = &expanded_keys[14];
        Self::sub_bytes(block, &SBOX);
        Self::shift_rows(block, &SHIFT_ROWS);
        Self::add_round_key(final_key, block);
          
    }


    fn decrypt (expanded_keys: &Vec<[u8; 16]>, block: &mut [u8]) {

        let final_key = &expanded_keys[14];
        Self::add_round_key(final_key, block);
        Self::shift_rows(block, &INV_SHIFT_ROWS);
        Self::sub_bytes(block, &INV_SBOX);
   
        let mut i: usize = 13;

        while i >= 1 {
            let keys = &expanded_keys[i];

            Self::add_round_key(keys, block);
            Self::mix_column(block, false);
            Self::shift_rows(block, &INV_SHIFT_ROWS);
            Self::sub_bytes(block, &INV_SBOX);

            i -= 1;
        }

        let master_key = &expanded_keys[0];
        Self::add_round_key(master_key, block);
      
    }


    fn pad(data: &[u8], mode: bool) -> Vec<u8> {

        let length: usize = data.len();
        let needed_size: usize = 16 - (length % 16);

        if mode {
            let mut vec = vec![needed_size as u8; length + needed_size];
        
            for (i, val) in data.iter().enumerate() {
                vec[i] = *val;
            }
         
            vec
        }
        else {
            let vec = data.to_vec();
            vec
        }

     }

  
     fn unpad(vec: &mut Vec<u8>) -> Result<(), String> {   

        let mut i: usize = vec.len() - 1;
        let added_val = vec[i];
       
        let mut num: u8 = 1;

        loop {
            
            if  num <= added_val {
                if vec[i] == added_val {
                    vec.pop();
                    num += 1;
                }
                else {
                    return Err("Invalid padding".into());
                }
            }
            else if num > added_val {
                return Ok(());
            }

            i -= 1;           
        }

    }    


    fn get_cpu_info() -> (usize, usize, usize) {

        let cores = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        let mb_per_core = if cores > 8 { 4 } 
        else { 1 };

        let min = mb_per_core * 1024 * 1024;
        let max = cores * min;

        (cores, min, max)
    }


    pub fn set_mode(&mut self, mode: &str) {
        self.mode = if mode == "encrypt" { true }
            else { false };
    }


    pub fn set_stream(&mut self, mode: bool) {
        self.stream = mode;
    }

    
    pub fn process(&self, data: &[u8]) -> Vec<u8> {
 
       if data.is_empty() {
            return vec![];
        }

        let mode = self.mode;
                
        let mut converted_data = if !self.stream {
            Self::pad(&data, mode)
        }
        else {
            data.to_vec()
        };

        let (total_threads, min, max) = Self::get_cpu_info();
        
        let length = converted_data.len();
        let total_blocks = length / 16;
        let whole_num = total_blocks / total_threads;
        
        let size: usize = if whole_num == 0 { min }
        else { max };

        thread::scope(|s| {

            for block in converted_data.chunks_mut(size) {
                s.spawn(move || {
                    let cloned_key = Arc::clone(&self.expanded_key);
                    let expanded_key = &*cloned_key;
                    
                    for new_block in block.chunks_mut(16) {

                        if mode {
                            Self::encrypt(expanded_key, new_block);
                        }
                        else {
                            Self::decrypt(expanded_key, new_block);
                        }

                    }
                });

             }
        });


        if !mode && !self.stream {
            let _ = Self::unpad(&mut converted_data);
        }

        converted_data
            
    }


    pub fn file(&mut self, input_path: &str) -> Result<(), String> {

        let data = fs::read(input_path);
        let vec: Vec<u8>;

        match data {
            Ok(val) => { vec = val; },
            Err(_) => { 
                let message = format!("\n[FILE ERROR] >> {} does not exists", input_path);
                return Err(message);
            },
        }

        if vec.is_empty() {
         
            let mut file_name = input_path.to_string();
            file_name.push_str(".enc");

            let _ = fs::write(file_name, "".as_bytes());

            Ok(())
        }
        else {
            let file_name: String;

            let mut result = if self.mode {
                let mut temp_vec = Self::pad(input_path.as_bytes(), true);

                let mut name = input_path.to_string();
                name.push_str(".enc");
                file_name = name;

                temp_vec.extend_from_slice(&vec);

                self.process(&temp_vec)
            }
            else {
                let decrypted = self.process(&vec);
                let mut temp_vec = (&decrypted[0..256]).to_vec();

                let _ = Self::unpad(&mut temp_vec);

                let try_file = String::from_utf8(temp_vec);

                match try_file {
                    Ok(val) => { file_name = val; },
                    Err(_) => { return Err("Invalid File".into()); },
                }

                (&decrypted[256..]).to_vec()
            };

            let _ = fs::write(file_name, &mut result);
            
            Ok(())
        }
    }
  

    pub fn file_stream(&mut self, input: &str) -> Result<(), String> {
        self.stream = true;

        let mode = self.mode;
        let (_, min, max) = Self::get_cpu_info();
    
        let mut file = File::open(input).unwrap();
        let length = file.metadata().unwrap().len() as usize;

        let mut reader = BufReader::new(file);
   
        let mut writer = if mode {
            let mut file_name: String = input.to_string();
            let pad = Self::pad(file_name.as_bytes(), true);

            file_name.push_str(".enc");

            let mut sub_writer = BufWriter::new(File::create(&file_name).unwrap());

            sub_writer.write_all(&pad);
            sub_writer
        }
        else {
            let mut buffer = vec![0u8; 256];
            let _ = reader.read_exact(&mut buffer).unwrap();

            let _ = Self::unpad(&mut buffer);
            let file_name = String::from_utf8(buffer).unwrap();
    
            BufWriter::new(File::create(file_name).unwrap())
        };

        let mut buffer = vec![0u8; max];

        let whole_num = length / max;
        let mut remainder = if whole_num > 0 { length % max }
        else { length };

        let mut i: usize = 0;

        if !mode {
            reader.seek(SeekFrom::Start(256)).unwrap();
            remainder -= 256;
        }

        loop {
            let total_size = reader.read(&mut buffer).unwrap();
            if total_size == 0 { break; }

            let to_process = &buffer[..total_size];
          
            let mut result: Vec<u8> = Vec::with_capacity(total_size);
    
            if i == whole_num {
                if remainder == total_size || remainder == 0 {

                   if mode {
                       let res = self.process(&Self::pad(to_process, true));
                       result.extend(res);
                   }
                   else { 
                       let res = self.process(to_process);
                       result.extend(res);
                       let _ = Self::unpad(&mut result);
                   }

                }
                else {
                    result.extend(self.process(to_process));
                }
            }
            else { 
                result.extend(self.process(to_process));
            }      

            writer.write_all(&mut result);
                  
            i += 1;       
           
        }

        writer.flush().unwrap();
        Ok(())
    
    }



   
}


#[cfg(test)]
mod tests {
   use crate::CipherX;
   use crate::cipherx::cipherx::{SBOX, INV_SBOX, SHIFT_ROWS, INV_SHIFT_ROWS};

    #[test]
    fn create_256_bytes_test() {
       let pass1 = "password1".as_bytes();

       let block1 = CipherX::create_32_bytes(pass1);
       let block1_again = CipherX::create_32_bytes(pass1);
       
        assert_eq!(32, block1.len());
        assert_eq!(block1, block1_again);

        let pass2 = "password2".as_bytes();
        let block2 = CipherX::create_32_bytes(pass2);

        assert_ne!(block1, block2);
        assert!(block1.iter().any(|&b| b != 0));
    }


    #[test]
    fn create_salt_test() {
        let mut pass = CipherX::create_32_bytes("passqwerty".as_bytes());

        let mut salt1 = [0u8; 32];
        let mut salt2 = [0u8; 32];

        CipherX::create_salt(&mut pass, &mut salt1);
        CipherX::create_salt(&mut pass, &mut salt2);

        assert_eq!(salt1, salt2);
        
        let mut pass2 = CipherX::create_32_bytes("qwertypass".as_bytes());
        let mut salt3 = [0u8; 32];
        CipherX::create_salt(&mut pass2, &mut salt3);

        assert_ne!(salt1, salt3);
    }


    #[test]
    fn create_master_key_test() {
        let mut pass = CipherX::create_32_bytes("master_key_password".as_bytes());

        let mut salt1 = [0u8; 32];
        let mut salt2 = [0u8; 32];

        CipherX::create_master_key(&mut pass, &mut salt1);
        CipherX::create_master_key(&mut pass, &mut salt2);

        assert_eq!(salt1, salt2);
       
        let mut pass2 = CipherX::create_32_bytes("master_key_password2".as_bytes());
        let mut salt3 = [0u8; 32];
        CipherX::create_master_key(&mut pass2, &mut salt3);
        println!("Key1 : {:?}", salt1);
        println!("Key3 : {:?}", salt3);

        assert_ne!(salt1, salt3);

    }


    #[test]
    fn create_expanded_key_test() {
        let key = [1u8; 32]; 
        let expanded = CipherX::create_expanded_key(&key);

        assert_eq!(expanded.len(), 15);
        assert_eq!(&expanded[0], &key[..16]);

        let expanded2 = CipherX::create_expanded_key(&key);
        assert_eq!(expanded, expanded2);

        let key2 = [2u8; 32];
        let expanded3 = CipherX::create_expanded_key(&key2);
        assert_ne!(expanded, expanded3);
    }


    #[test]
    fn get_keys_test() {
        let cipherx = CipherX::new("user", "password");

        let master_key = cipherx.get_master_key();
        let expanded_key = cipherx.get_expanded_key();

        assert_eq!(master_key.len(), 32);
        assert_eq!(expanded_key.len(), 15);

        assert_eq!(master_key, cipherx.get_master_key());
        assert_eq!(expanded_key, cipherx.get_expanded_key());
    }


    #[test]
    fn add_round_key_test() {
        let key = vec![1u8; 16];
        let mut block = vec![2u8; 16];
        let expected_block1 = vec![3u8; 16];

        CipherX::add_round_key(&key, &mut block);

        assert_eq!(block, expected_block1);
        
        // the original block
        let expected_block2 = vec![2u8; 16];
        CipherX::add_round_key(&key, &mut block);
        assert_eq!(block, expected_block2);

    }


    #[test]
    fn sub_bytes_test() {
        let original_data: Vec<u8> = (1..=16).collect();
        let mut block = original_data.clone();
        
        // to encrypt, block will be equal to SBOX table
        CipherX::sub_bytes(&mut block, &SBOX);
        
        // to decrypt, block will go back to original
        CipherX::sub_bytes(&mut block, &INV_SBOX);
        assert_eq!(block, original_data);
    }

    
    #[test]
    fn test_shift_rows() {
        let original_data: Vec<u8> = (1..=16).collect();
        let mut block = original_data.clone();
        
        // to encrypt
        CipherX::shift_rows(&mut block, &SHIFT_ROWS);
        
        // to decrypt
        CipherX::shift_rows(&mut block, &INV_SHIFT_ROWS);

        assert_eq!(block, original_data);
    }


   #[test]
    fn mix_column_test() {
    let original_data: Vec<u8> = (1..=16).collect();
    let mut block = original_data.clone();
    
    // to encrypt
    CipherX::mix_column(&mut block, true); 

    // to decrypt
    CipherX::mix_column(&mut block, false);

    assert_eq!(block, original_data);
    }


    #[test]
    fn padding_test() {
        let vec = vec![16u8; 100_000_000];
        let length = vec.len();

        let padded_vec = CipherX::pad(&vec, true);
        let needed_size: usize = 16 - (length % 16);
        
        assert_eq!(padded_vec.len(), (length + needed_size));
    }


    #[test]
    fn unpadding_test() {
        let vec = vec![16u8; 100_000_000];
        let length = vec.len();

        let mut padded_vec = CipherX::pad(&vec, true);

        let _ = CipherX::unpad(&mut padded_vec).unwrap();

        assert_eq!(length, vec.len());

    }


}



