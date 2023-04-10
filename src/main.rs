// [SM3 Digest Programme]
// Author: XiangXin
// E-mail: ictxiangxin@hotmail.com
// File: main.rs

use std::env;
use std::io::Error;

mod sm3_digest;
mod sm3_utils;

fn binary_to_hex_string(data: [u8; 32]) -> String {
    let mut hex_string: String = String::new();
    fn byte_to_hex(byte: u8) -> char {
        if byte < 10 { (b'0' + byte) as char } else { (b'A' + byte - 10) as char }
    }
    for byte in data {
        hex_string.push(byte_to_hex(byte / 16));
        hex_string.push(byte_to_hex(byte % 16));
    }
    hex_string
}

fn usage() {
    println!("SM3 Digest Programme(By XiangXin)");
    println!("Usage:");
    println!("    sm3 [-s|-f] [String|File]");
    println!("    -s Compute String SM3 Digest.");
    println!("    -f Compute File SM3 Digest.");
}

fn main() {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() != 3 {
        usage();
        return;
    }
    match arguments[1].as_str() {
        "-s" => {
            let digest_binary: [u8; 32] = sm3_utils::SM3Utils::sm3_data_digest(arguments[2].as_bytes());
            print!("{}", binary_to_hex_string(digest_binary));
        }
        "-f" => {
            let digest_binary: Result<[u8; 32], Error> = sm3_utils::SM3Utils::sm3_file_digest(&arguments[2]);
            match digest_binary {
                Ok(binary) => print!("{}", binary_to_hex_string(binary)),
                Err(error) => println!("Error: {error:?}"),
            }
        }
        _ => usage(),
    }
}
